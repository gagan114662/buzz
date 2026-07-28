//! Boot reconciliation and the live ladder state for the running process.
//!
//! `boot` runs before Tauri is built, while the process is still single
//! threaded and owns no D-Bus name — both things it may do (hand off to a child
//! with a different environment, or exit for `--reset-rendering-mode`) require
//! that. What it returns is either a `Session`, which the rest of the process
//! uses to react to a crash, or an instruction to exit.

mod handoff;

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::classify::{self, Decision};
use super::cli;
use super::dbus::{self, Observation};
use super::episode::{self, Advance, Claimed, Episode, Termination};
use super::launcher::{self, Handoff, Refusal, Tag};
use super::profiles::{self, Env, Package, Tier};
use super::state::{Expected, Next, Phase, Record, Refused, Store};
use super::LOG;

/// Why the ladder is not running this launch. In every case the app starts
/// normally with whatever environment it already has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Disabled {
    /// The user assigned an owned variable. Their configuration wins whole: no
    /// tier selection, no relaunch, no ladder.
    UserEnv(Vec<String>),
    /// No app data dir, so no durable record is possible.
    NoStateDir(String),
}

impl std::fmt::Display for Disabled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Disabled::UserEnv(vars) => write!(
                f,
                "{} set in the environment; renderer recovery leaves user \
                 configuration alone",
                vars.join(", ")
            ),
            Disabled::NoStateDir(error) => write!(f, "{error}"),
        }
    }
}

/// What `boot` concluded.
pub(crate) enum Boot {
    /// Continue in this process. The environment already matches the session's
    /// tier, and the session carries what is needed to react to a later crash.
    Run(Arc<Session>),
    /// A child was spawned to run the selected tier; this process must exit
    /// without starting the app. The child is Buzz now.
    HandedOff,
    /// `--reset-rendering-mode` did its work. Exit without launching.
    Reset,
    /// Recovery is off this launch, but the app still starts.
    Off(Disabled),
    /// Another process owns this episode. Exit without starting the app and
    /// without competing for the single-instance name. The reason is already
    /// logged where it was decided, so nothing is carried here.
    Superseded,
    /// The user asked for something that cannot be delivered. Exit before Tauri
    /// with a diagnostic and a non-zero status rather than starting an app that
    /// silently ignores the request.
    Fatal(String),
}

/// Everything the running process needs to react to a web-process crash.
pub(crate) struct Session {
    store: Store,
    package: Package,
    version: String,
    dbus_name: String,
    args: Vec<OsString>,
    /// The tier this process is actually running.
    tier: usize,
    /// Episode identity, present only when this process claimed a prepared
    /// record. A plain launch owns no episode.
    episode: Option<Episode>,
    /// Manual override: never advance, never persist. Set by `--safe-rendering`
    /// and by any child that could not claim the episode it was sent to run.
    frozen: bool,
    /// Set once a ladder-eligible crash is seen, so a process that observed one
    /// and failed to hand off never goes on to record a crash-free startup, and
    /// so the handoff itself happens at most once per process.
    crashed: AtomicBool,
    /// When this process started, for the crash-eligibility window.
    launched: std::time::Instant,
    /// The spawn edge. Always `launcher::spawn` in production; tests replace it
    /// so a refusal or a success can be driven without forking.
    launch: launcher::Launch,
}

/// What this process must give up before a child may take the single-instance
/// name — and, decisively, whether giving it up can be undone.
///
/// The two callers of the launcher sit on opposite sides of that question, and
/// a bare closure could not tell them apart: at boot no name is held yet, so a
/// refusal is harmless, while a live app has to destroy its single-instance
/// plugin and can never re-register it. Naming the distinction here is what
/// stops a refusal from being mistaken for a recoverable one.
enum Release<'a> {
    /// Boot, before Tauri exists. Nothing is held, so nothing is released.
    NothingHeld,
    /// A live app holding the name. Running this destroys the single-instance
    /// plugin; there is no way back.
    SingleInstanceName(&'a dyn Fn()),
}

impl Release<'_> {
    /// Release, and report whether the process just crossed an irreversible
    /// boundary.
    fn run(&self) -> bool {
        match self {
            Release::NothingHeld => false,
            Release::SingleInstanceName(destroy) => {
                destroy();
                true
            }
        }
    }
}

/// A durable write was refused because the record no longer matches the state
/// its caller decided from — another process reset it, or a newer episode
/// superseded it.
///
/// Nothing was released and nothing was spawned when this comes back: the
/// prepared write is the first thing a handoff does, before the release and the
/// spawn. Boot answers it by deciding again from the new state; the live crash
/// path answers it by standing down, since a process whose episode has been
/// superseded is not the one that should be laddering.
///
/// Carries the description rather than the record it found, because describing
/// what changed is all any caller does with it.
struct Stale(String);

impl std::fmt::Display for Stale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which state a durable write is allowed to replace.
///
/// The two callers differ in kind, not merely in value. Boot reconciliation acts
/// on a record it read *earlier* and must prove that exact record is still
/// current. The live crash path acts on a crash that just happened, and its
/// source is its own episode wherever the chain has reached — it holds no
/// earlier snapshot to be stale about. Naming the distinction is what stops a
/// classified snapshot from silently standing in for a fresh read.
#[derive(Clone, Copy)]
enum Source<'a> {
    /// Exactly this record, or the write is refused. `None` expects no record.
    Classified(Option<&'a Record>),
    /// This process's own episode, at the phase a `prepared` write must follow.
    OwnEpisode,
}

/// What one reconciliation round settled on, once any durable write it needed
/// has landed.
///
/// Carries no `Session`: the loop holds that by `&mut`, so a round that has to
/// be retaken does not have to move an owned value out and back.
enum Settled {
    /// Run in this process, with whatever tier and freeze the round selected.
    RunHere,
    /// A child carrying the selected tier is Buzz now; this process exits.
    HandedOff,
    /// Exit before Tauri with this diagnostic.
    Fatal(String),
}

/// How many times boot reconciliation re-decides before standing down.
///
/// This is not a spin: a refusal only happens when another process durably
/// changed the record, so every round is somebody else's progress. Standing
/// down runs the launched profile untracked — the one outcome that is always
/// safe, because it writes nothing and still starts the app.
const RECONCILE_ATTEMPTS: usize = 3;

/// What a live app must do about a web-process termination.
pub(crate) enum CrashResponse {
    /// A child carrying the next tier is Buzz now. Exit.
    HandedOff,
    /// The relaunch was refused *after* the single-instance name was released.
    /// This process no longer owns the name it needs to be the app, and cannot
    /// take it back, so it must exit rather than linger as a second instance.
    Stranded,
    /// Nothing was released and nothing was launched. Carry on.
    Continue,
}

/// Reconcile persisted state and select this launch's renderer tier.
///
/// `identifier` is the bundle identifier, which names both the app data dir and
/// the single-instance bus name; `version` invalidates a persisted tier across
/// an upgrade.
pub(crate) fn boot(identifier: &str, version: &str) -> Boot {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let app_data_dir = dirs::data_dir()
        .map(|dir| dir.join(identifier))
        .ok_or_else(|| "no user data directory".to_string());
    let boot = reconcile(
        app_data_dir,
        identifier,
        version,
        args,
        &|key| {
            // `var_os`, not `var`: presence is the test, and a non-UTF-8 value
            // is still a user assignment.
            std::env::var_os(key).map(|value| value.to_string_lossy().into_owned())
        },
        launcher::spawn,
    );
    if let Boot::Off(reason) = &boot {
        eprintln!("{LOG}: disabled — {reason}");
    }
    boot
}

/// `boot` with its environmental inputs supplied, so the decision path is
/// exercisable without touching the real process environment.
pub(super) fn reconcile(
    app_data_dir: Result<std::path::PathBuf, String>,
    identifier: &str,
    version: &str,
    args: Vec<OsString>,
    env: Env<'_>,
    launch: launcher::Launch,
) -> Boot {
    let flags = cli::parse(args.iter().map(OsString::as_os_str));
    let package = Package::detect(env);
    let tag = Tag::read(env);

    let app_data_dir = match app_data_dir {
        Ok(dir) => dir,
        Err(error) => return Boot::Off(Disabled::NoStateDir(error)),
    };

    let session = Session {
        store: Store::new(&app_data_dir),
        package,
        version: version.to_string(),
        dbus_name: dbus::single_instance_name(identifier),
        args,
        tier: 0,
        episode: None,
        frozen: false,
        crashed: AtomicBool::new(false),
        launched: std::time::Instant::now(),
        launch,
    };

    // Reset runs ahead of the opt-out check on purpose: a user who has set an
    // owned variable is exactly the user most likely to be clearing a record
    // that an earlier run left behind.
    if flags.reset_rendering_mode {
        return session.reset();
    }

    // A recovery child never reinterprets the variables its parent injected as
    // user configuration, so only an untagged launch checks for a user opt-out.
    if tag.is_none() {
        let present = profiles::owned_present(package, env);
        if !present.is_empty() {
            // `--safe-rendering` and a user-set owned variable are two
            // incompatible answers to the same question, and the ladder has no
            // basis for picking one: honouring the flag would overwrite
            // configuration the user typed, and honouring the environment would
            // silently ignore a rescue flag from a user whose app will not
            // start. So neither is guessed — the request is refused, loudly,
            // before Tauri.
            return match flags.safe_rendering {
                true => Boot::Fatal(conflict_message(&present)),
                false => Boot::Off(Disabled::UserEnv(present)),
            };
        }
    }

    match tag {
        Some(tag) => session.start_as_child(tag),
        None => session.select_tier(flags.safe_rendering),
    }
}

/// The diagnostic for `--safe-rendering` against a user-set owned variable.
///
/// `present` carries `KEY=value` assignments, so it both shows the user what is
/// set and names the keys to unset — the two things needed to act on this.
fn conflict_message(present: &[String]) -> String {
    let keys: Vec<&str> = present
        .iter()
        .map(|assignment| match assignment.split_once('=') {
            Some((key, _)) => key,
            None => assignment.as_str(),
        })
        .collect();
    format!(
        "{} cannot be applied: {} already set in the environment. \
         Either unset {} and run {} again, or keep that environment and drop \
         the flag.",
        cli::SAFE_RENDERING,
        present.join(", "),
        keys.join(", "),
        cli::SAFE_RENDERING,
    )
}

impl Session {
    /// `--reset-rendering-mode`: delete the persisted tier and episode state,
    /// say what was cleared, and exit without launching.
    fn reset(self) -> Boot {
        let tx = match self.store.lock() {
            Ok(tx) => tx,
            Err(error) => {
                // Another process is mid-transition. Clearing without the lock
                // could delete a record a live child is about to claim, so this
                // reports the refusal rather than racing it.
                return Boot::Fatal(format!("could not clear renderer state: {error}"));
            }
        };
        // Reading the source inside the transaction that clears it is what makes
        // reset an ordering boundary: it cannot be stale, and any decision taken
        // from the state it deletes is refused when that decision tries to write.
        let cleared = self.store.exists(&tx);
        let source = self.store.read();
        if let Err(error) =
            self.store
                .transition(&tx, source.as_ref().map(Expected::of), Next::Cleared)
        {
            return Boot::Fatal(format!("could not clear renderer state: {error}"));
        }
        println!(
            "{}",
            match cleared {
                true => "Cleared the persisted renderer profile and episode state.",
                false => "No persisted renderer profile or episode state to clear.",
            }
        );
        Boot::Reset
    }

    /// Untagged launch: decide from the durable record, then either run the
    /// selected tier here or hand off to a child that can.
    ///
    /// Deciding and acting are two steps with a D-Bus round trip between them,
    /// so the record can move in between — another launch's reset, or a newer
    /// episode. Every write therefore names the record it was decided from and
    /// is refused if that record is gone, and a refusal re-decides from what is
    /// there now rather than proceeding on a decision about a state that no
    /// longer exists.
    fn select_tier(mut self, safe_rendering: bool) -> Boot {
        // `--safe-rendering` is a manual override for this launch only: the
        // terminal tier, no episode, nothing persisted. It reads no record, so
        // there is nothing for it to be stale about.
        if safe_rendering {
            self.tier = self.package.terminal_tier();
            self.frozen = true;
            eprintln!(
                "{LOG}: {} — forcing {} for this launch only",
                cli::SAFE_RENDERING,
                self.profile_name()
            );
            return match self.hand_off_or_run(None, self.tier, None) {
                Ok(Settled::RunHere) => Boot::Run(Arc::new(self)),
                Ok(Settled::HandedOff) => Boot::HandedOff,
                Ok(Settled::Fatal(diagnostic)) => Boot::Fatal(diagnostic),
                // A forced launch prepares no record, so it has nothing to be
                // stale about; `hand_off_or_run` cannot refuse it this way.
                Err(stale) => Boot::Fatal(format!("renderer state changed unexpectedly: {stale}")),
            };
        }

        for attempt in 1..=RECONCILE_ATTEMPTS {
            match self.reconcile_once() {
                Ok(Settled::RunHere) => return Boot::Run(Arc::new(self)),
                Ok(Settled::HandedOff) => return Boot::HandedOff,
                Ok(Settled::Fatal(diagnostic)) => return Boot::Fatal(diagnostic),
                Err(stale) => {
                    eprintln!(
                        "{LOG}: renderer state changed under this launch ({stale}); \
                         re-reading it (attempt {attempt} of {RECONCILE_ATTEMPTS})"
                    );
                    // Nothing was released or spawned — a refused write is the
                    // first thing a handoff does — so the next round starts from
                    // the tier this process was actually launched as.
                    self.tier = 0;
                    self.frozen = false;
                }
            }
        }
        // Another process has out-raced this one repeatedly. Running the
        // launched profile untracked is the safe stand-down: it writes nothing,
        // so it cannot corrupt whatever that process is doing, and the app still
        // starts.
        eprintln!(
            "{LOG}: renderer state kept changing; running the launched profile \
             without tracking it"
        );
        self.tier = 0;
        self.frozen = true;
        Boot::Run(Arc::new(self))
    }

    /// One decide-then-act round. `Err` means the record moved before the write
    /// this decision called for could land, so the decision must be retaken.
    fn reconcile_once(&mut self) -> Result<Settled, Stale> {
        let Some(record) = self.store.read() else {
            // No record to be superseded, and a handoff from here prepares only a
            // freshly minted episode, which expects exactly this absence.
            return self.run_here_or_hand_off(None);
        };
        let decision = classify::decide(
            &record,
            &dbus::observe(&self.dbus_name),
            dbus::bus_id().as_deref(),
            &self.version,
            &pid_alive,
        );
        eprintln!(
            "{LOG}: found {:?} record (token={} gen={} tier={} profile={}) → {decision:?}",
            record.phase, record.token, record.generation, record.tier, record.profile
        );
        let source = Some(&record);

        match decision {
            // Another instance owns the app. Run on as an ordinary duplicate
            // and let the single-instance plugin forward argv and exit us.
            // Writes nothing, so nothing can be stale.
            Decision::Defer(_) => Ok(Settled::RunHere),
            Decision::DiscardAndBaseline { .. } => {
                self.clear_discarded(&record)?;
                // The record this decision was about is gone and the baseline is
                // what is left, so a fresh episode expects no record at all.
                self.run_here_or_hand_off(None)
            }
            // The persisted "last crash-free startup profile" fact.
            Decision::ReuseProfile { tier } => {
                self.tier = tier;
                self.run_here_or_hand_off(source)
            }
            // No profile survived. Stop rather than relaunch: this process is
            // the baseline environment, and the user's way to the safest tier
            // is the flag, not another fork. Writes nothing.
            Decision::StopExhausted { tier } => {
                self.frozen = true;
                eprintln!(
                    "{LOG}: the ladder was already exhausted at tier {tier} on {}; \
                     relaunch with {} to force the safest profile",
                    self.package.label(),
                    cli::SAFE_RENDERING
                );
                Ok(Settled::RunHere)
            }
            // An attempt that never produced a receipt: re-run the same tier
            // under the next generation.
            Decision::RetrySameTier { tier, .. } => {
                self.tier = tier;
                self.hand_off_or_run(Some(episode::retry_of(&record)), tier, source)
            }
            Decision::AdvanceOrStop { tier, .. } => self.step_down(tier, &record),
        }
    }

    /// Discard a record this launch cannot use — a different app version's.
    ///
    /// Named source, so a delayed version-mismatch decision cannot delete an
    /// episode that a newer launch prepared while this one was classifying.
    fn clear_discarded(&self, source: &Record) -> Result<(), Stale> {
        let tx = self
            .store
            .lock()
            .map_err(|error| Stale(format!("the state lock was unavailable: {error}")))?;
        match self
            .store
            .transition(&tx, Some(Expected::of(source)), Next::Cleared)
        {
            Ok(()) => Ok(()),
            Err(error @ Refused::Stale(_)) => Err(Stale(error.to_string())),
            Err(error) => {
                eprintln!("{LOG}: could not discard the stale record — {error}");
                Ok(())
            }
        }
    }

    /// Continue here when this process already carries the selected tier's
    /// environment, otherwise hand off to a child that carries it exactly.
    fn run_here_or_hand_off(&mut self, source: Option<&Record>) -> Result<Settled, Stale> {
        if self.tier == 0 {
            // Tier 0 sets nothing, and the opt-out check above proved no owned
            // variable is present — this process already *is* tier 0.
            return Ok(Settled::RunHere);
        }
        // A frozen launch is a manual override, so it runs the tier without
        // owning an episode: no record, no receipt, no advance.
        let episode = (!self.frozen).then(episode::fresh);
        let tier = self.tier;
        self.hand_off_or_run(episode, tier, source)
    }

    /// Move one tier down for a failed attempt, or stop at the terminal tier.
    fn step_down(&mut self, failed: usize, source: &Record) -> Result<Settled, Stale> {
        match episode::advance(self.package, failed) {
            Advance::Tier(next) => {
                self.tier = next;
                self.hand_off_or_run(Some(episode::fresh()), next, Some(source))
            }
            Advance::Exhausted => {
                self.tier = failed;
                self.frozen = true;
                // Named source: an `exhausted` write is terminal, so writing it
                // over a record that has since been reset or superseded would
                // strand the ladder on a decision about state that is gone.
                self.note_exhausted(Source::Classified(Some(source)))?;
                Ok(Settled::RunHere)
            }
        }
    }

    /// Recovery-child path: exclusively claim the record this child was
    /// launched for, and record `started` as its first action.
    fn start_as_child(mut self, tag: Tag) -> Boot {
        let Some(tier) = self.package.tier_named(&tag.profile) else {
            // Nothing here can be trusted to describe the environment the
            // parent actually applied, so this launch is not tracked at all.
            eprintln!(
                "{LOG}: recovery tag names an unknown profile ({}); not tracking this launch",
                tag.profile
            );
            self.frozen = true;
            return Boot::Run(Arc::new(self));
        };
        self.tier = tier;

        // A forced child owns no episode, so it has nothing to claim — it just
        // runs the environment it was handed.
        let Some(episode) = tag.episode else {
            self.frozen = true;
            return Boot::Run(Arc::new(self));
        };

        match episode::claim(&self.store, &episode) {
            Claimed::Owner { episode, tier } => {
                self.tier = tier;
                self.episode = Some(episode);
                Boot::Run(Arc::new(self))
            }
            // Someone else owns this episode. Exiting here rather than running
            // on is the point: a loser that continued into Tauri could win the
            // single-instance name ahead of the true owner, and the owner would
            // then exit as a duplicate while the durable `started` receipt still
            // named it — a record pointing at a dead process, which the next
            // launch reads as a failed handoff and charges to the ladder.
            Claimed::Superseded(reason) => {
                eprintln!("{LOG}: recovery child is not the episode owner — {reason}; exiting");
                Boot::Superseded
            }
            // No owner to defer to, so exiting would cost the user their window
            // for nothing. Run the environment that was handed over, untracked.
            Claimed::Untracked(reason) => {
                eprintln!("{LOG}: not tracking this recovery launch — {reason}");
                self.frozen = true;
                Boot::Run(Arc::new(self))
            }
        }
    }

    pub(crate) fn profile_name(&self) -> &'static str {
        self.package.tier(self.tier).map(|t| t.name).unwrap_or("")
    }

    /// Record that this process holds the single-instance name.
    pub(crate) fn note_owned(&self) {
        self.note(Phase::Owned);
    }

    /// How long this process still has before it counts as a crash-free start.
    pub(crate) fn until_confirmation(&self) -> std::time::Duration {
        episode::CRASH_ELIGIBILITY_WINDOW.saturating_sub(self.launched.elapsed())
    }

    /// Record that this process outlived the crash-eligibility window — the
    /// "last crash-free startup profile" fact. Version-scoped, and never a
    /// claim that rendering is actually correct.
    pub(crate) fn note_confirmed(&self) {
        if self.crashed.load(Ordering::SeqCst) {
            // An eligible crash was seen and the handoff did not carry us away.
            // Recording this tier as crash-free would persist the opposite of
            // what happened.
            return;
        }
        self.note(Phase::Confirmed);
    }

    /// Write a phase receipt for the episode this process owns.
    ///
    /// The transition names both the episode and the phase the receipt follows,
    /// which is two rejections in one. Identity: `note_confirmed` runs from a
    /// timer thread and can be racing a crash handoff that already prepared the
    /// next token, and without the check it would overwrite that token with the
    /// superseded episode's `confirmed`. Order: the chain is exact, so a receipt
    /// that skips its predecessor — a `confirmed` after a failed `owned` write,
    /// or an out-of-order callback — is refused rather than accepted as
    /// "forward".
    ///
    /// The receipt is bound to the bus id as well as the unique name: a unique
    /// name like `:1.4` only identifies a connection on the bus that issued it,
    /// so without the bus id a receipt from an earlier session's bus could
    /// correlate against a stranger here.
    fn note(&self, phase: Phase) {
        let Some(episode) = &self.episode else {
            return;
        };
        let Some(follows) = episode::predecessor_of(phase) else {
            // Only `prepared` and `exhausted` have no predecessor, and neither is
            // written through here.
            return;
        };
        let Ok(tx) = self.store.lock() else {
            eprintln!("{LOG}: skipping the {phase:?} receipt — the state lock was unavailable");
            return;
        };

        let mut record = self.record(phase, episode);
        record.pid = Some(std::process::id());
        match dbus::observe(&self.dbus_name) {
            Observation::Owned(owner) => {
                record.unique_name = Some(owner.unique_name);
                record.bus_id = dbus::bus_id();
            }
            // Not owning the name does not block the receipt: the phase itself
            // is still true, and `classify` reads a receipt with no recorded
            // identity as uncorrelatable rather than as ours.
            _ => eprintln!("{LOG}: writing {phase:?} without an owner identity"),
        }
        let expected = Expected::after(&episode.token, episode.generation, follows);
        if let Err(error) = self
            .store
            .transition(&tx, Some(expected), Next::Record(&record))
        {
            eprintln!("{LOG}: skipping the {phase:?} receipt — {error}");
        }
    }

    /// React to a web-process termination.
    pub(crate) fn on_web_process_terminated(
        &self,
        termination: Termination,
        destroy_single_instance: &dyn Fn(),
    ) -> CrashResponse {
        let elapsed = self.launched.elapsed();
        if !episode::advances_ladder(termination, elapsed) {
            eprintln!(
                "{LOG}: web process ended ({termination:?}) {elapsed:?} after launch \
                 at tier {} ({}) — not ladder-eligible",
                self.tier,
                self.profile_name()
            );
            return CrashResponse::Continue;
        }
        // One-shot: the signal can fire again while a handoff is in flight (a
        // second webview, or WebKit respawning and re-crashing), and a second
        // handoff would spawn a second child for a second episode — two live
        // Buzz processes racing one name. `swap` makes the first caller the only
        // one that proceeds; later callers still see `crashed` set, so they also
        // suppress the crash-free receipt.
        if self.crashed.swap(true, Ordering::SeqCst) {
            eprintln!("{LOG}: a ladder-eligible crash was already handled; not advancing again");
            return CrashResponse::Continue;
        }
        if self.frozen {
            eprintln!("{LOG}: not advancing — this launch is running a forced profile");
            return CrashResponse::Continue;
        }

        match episode::advance(self.package, self.tier) {
            Advance::Exhausted => {
                // A stale terminal write means this process's episode was
                // superseded while it ran. Nothing to do: the process that
                // superseded it owns the ladder now.
                if let Err(stale) = self.note_exhausted(Source::OwnEpisode) {
                    eprintln!("{LOG}: not recording the exhausted ladder — {stale}");
                }
                CrashResponse::Continue
            }
            Advance::Tier(next) => {
                let release = Release::SingleInstanceName(destroy_single_instance);
                let handoff =
                    match self.hand_off(episode::fresh(), next, Source::OwnEpisode, &release) {
                        Ok(handoff) => handoff,
                        // Refused before anything was released or spawned, so this
                        // process still owns its name. Another process superseded
                        // this episode, which means it is already driving the
                        // ladder — advancing here too would fork it.
                        Err(stale) => {
                            eprintln!(
                            "{LOG}: not advancing the ladder — {stale}; another launch owns it now"
                        );
                            return CrashResponse::Continue;
                        }
                    };
                match handoff {
                    Handoff::Launched => CrashResponse::HandedOff,
                    // Nothing was released, so this process is still the app.
                    Handoff::RefusedBeforeRelease(refusal) => {
                        eprintln!("{LOG}: relaunch refused: {refusal}");
                        CrashResponse::Continue
                    }
                    // The single-instance plugin is destroyed and cannot be
                    // re-registered. Staying would leave a Buzz that no longer
                    // owns the name — a later launch would start a second app
                    // beside it, and deep links would go to whichever won.
                    Handoff::RefusedAfterRelease(refusal) => {
                        eprintln!(
                            "{LOG}: relaunch refused after releasing the single-instance name \
                             ({refusal}); exiting rather than running without it"
                        );
                        CrashResponse::Stranded
                    }
                }
            }
        }
    }

    fn rung(&self, tier: usize) -> Result<&'static Tier, Refusal> {
        self.package
            .tier(tier)
            .ok_or_else(|| Refusal::NoTier(format!("{} has no tier {tier}", self.package.label())))
    }

    /// The state a `prepared` write may replace.
    ///
    /// A classified source must still be exactly what was decided from. A live
    /// crash path holds no earlier snapshot: it names its own episode, or — when
    /// this process owns none, which is every tier-0 launch — whatever the
    /// transaction just read, since there is no earlier decision to be stale
    /// about.
    fn expected<'a>(
        &'a self,
        source: Source<'a>,
        current: Option<&'a Record>,
    ) -> Option<Expected<'a>> {
        match source {
            Source::Classified(source) => source.map(Expected::of),
            Source::OwnEpisode => match &self.episode {
                Some(episode) => Some(Expected::attempt(&episode.token, episode.generation)),
                None => current.map(Expected::of),
            },
        }
    }

    /// Record that no profile survived, so later launches stop here instead of
    /// walking the whole ladder again on every start.
    ///
    /// `Exhausted` is terminal, so it is the one write that most needs a named
    /// source: stamping it over a record that has since been reset or superseded
    /// would stop the ladder on the strength of a decision about state that no
    /// longer exists.
    fn note_exhausted(&self, source: Source<'_>) -> Result<(), Stale> {
        let episode = self.episode.clone().unwrap_or_else(episode::fresh);
        let Ok(tx) = self.store.lock() else {
            eprintln!("{LOG}: could not record the exhausted ladder — the state lock was busy");
            return Ok(());
        };
        let current = self.store.read();
        let mut record = self.record(Phase::Exhausted, &episode);
        record.pid = Some(std::process::id());
        match self.store.transition(
            &tx,
            self.expected(source, current.as_ref()),
            Next::Record(&record),
        ) {
            Ok(()) => {}
            Err(error @ Refused::Stale(_)) => return Err(Stale(error.to_string())),
            Err(error) => eprintln!("{LOG}: could not record the exhausted ladder — {error}"),
        }
        eprintln!(
            "{LOG}: ladder exhausted on {} at tier {} ({}); \
             relaunch with {} to force the safest profile",
            self.package.label(),
            self.tier,
            self.profile_name(),
            cli::SAFE_RENDERING
        );
        Ok(())
    }

    fn record(&self, phase: Phase, episode: &Episode) -> Record {
        Record::new(
            phase,
            &episode.token,
            episode.generation,
            self.profile_name(),
            self.tier,
            &self.version,
        )
    }
}

fn pid_alive(pid: u32) -> bool {
    // Signal 0 runs the existence and permission checks without delivering
    // anything, and unlike a /proc lookup it is not fooled by a pid namespace.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}
