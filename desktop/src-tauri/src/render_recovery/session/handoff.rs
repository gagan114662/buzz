//! The handoff itself: preparing a record for a child, crossing the
//! single-instance release boundary, and undoing a preparation whose child was
//! never launched.
//!
//! Split out of `session` because it is one sequence with one invariant — the
//! record is durable before the child exists, and nothing that can fail runs
//! after the name is released — while `session` is about deciding *whether* to
//! run it.

use super::*;

impl Session {
    /// Hand off to a child at `tier`, or run on here if the handoff is refused.
    /// Only reached before Tauri exists, so nothing is held and every refusal
    /// leaves this process exactly as it was launched.
    pub(super) fn hand_off_or_run(
        &mut self,
        episode: Option<Episode>,
        tier: usize,
        source: Option<&Record>,
    ) -> Result<Settled, Stale> {
        let handed = match episode {
            Some(episode) => self.hand_off(
                episode,
                tier,
                Source::Classified(source),
                &Release::NothingHeld,
            )?,
            // A forced launch prepares nothing, so it has no source to be stale
            // about.
            None => self.force(tier),
        };
        match handed {
            Handoff::Launched => Ok(Settled::HandedOff),
            Handoff::RefusedBeforeRelease(refusal) => {
                eprintln!("{LOG}: staying at the launched profile — {refusal}");
                // The handoff did not happen, so this process is still the
                // baseline it was launched as and must not claim otherwise.
                self.tier = 0;
                self.frozen = true;
                Ok(Settled::RunHere)
            }
            // Unreachable by construction: `Release::NothingHeld` releases
            // nothing, so there is no post-release side to land on. Handled as a
            // refusal rather than a panic — if the invariant ever breaks, the
            // safe reading of "we may have released something" is to not run.
            Handoff::RefusedAfterRelease(refusal) => Ok(Settled::Fatal(format!(
                "renderer handoff refused after an unexpected release: {refusal}"
            ))),
        }
    }

    /// Prepare a record for `tier`, release the single-instance name, and spawn
    /// a child carrying the tier's exact environment.
    ///
    /// The order is the whole mechanism. The record must be durable before the
    /// child exists, because the child claims it as its first action and would
    /// otherwise find nothing. The name must be released before the probe,
    /// because a child that fails to take the name forwards its argv and exits
    /// 0 — indistinguishable from a successful handoff.
    ///
    /// The prepared write names `source`, so a handoff decided from a record
    /// that has since been reset or superseded is refused *before* anything is
    /// released or spawned — `Err(Stale)` therefore always means this process is
    /// untouched.
    pub(super) fn hand_off(
        &self,
        episode: Episode,
        tier: usize,
        source: Source<'_>,
        release: &Release<'_>,
    ) -> Result<Handoff, Stale> {
        let rung = match self.rung(tier) {
            Ok(rung) => rung,
            Err(refusal) => return Ok(Handoff::RefusedBeforeRelease(refusal)),
        };
        let tx = match self.store.lock() {
            Ok(tx) => tx,
            Err(error) => {
                return Ok(Handoff::RefusedBeforeRelease(Refusal::StateNotDurable(
                    error,
                )));
            }
        };
        let previous = self.store.read();
        let record = episode::prepare(&episode, self.package, tier, &self.version);
        match self.store.transition(
            &tx,
            self.expected(source, previous.as_ref()),
            Next::Record(&record),
        ) {
            Ok(()) => {}
            Err(error @ Refused::Stale(_)) => return Err(Stale(error.to_string())),
            Err(Refused::NotDurable(detail)) => {
                return Ok(Handoff::RefusedBeforeRelease(Refusal::StateNotDurable(
                    detail,
                )));
            }
        }
        if episode.generation == 0 {
            // Only now that the new record is durable. Pruning first would, on a
            // failed record write, leave the old record current with its claim
            // evidence already gone — and an old child that had passed its
            // record read could then re-create its claim and write a receipt
            // over the record.
            self.store.prune_claims(&tx, &episode.token);
        }
        // Released before the spawn: the record is durable and every check that
        // does not need the name released has already run.
        drop(tx);

        let tag = Tag {
            episode: Some(episode),
            profile: rung.name.to_string(),
        };
        let handoff = self.spawn_child(rung, &tag, release);
        if handoff.refused() {
            // No child exists, so the prepared record describes an attempt that
            // will never be claimed. Left in place it would spend the rung's one
            // retry on a failure that was never about rendering.
            self.roll_back(&record, previous);
        }
        Ok(handoff)
    }

    /// Restore the record a refused handoff had already overwritten.
    ///
    /// Identity-checked, because the lock is dropped between the prepared write
    /// and the spawn: by the time a refusal comes back, a concurrent launch may
    /// have prepared its own episode, and a blind restore would erase a record
    /// that a live child is about to claim — turning that child's handoff into
    /// an untracked launch. Only the record this call itself wrote is rolled
    /// back, which is exactly what naming it as the expected source says.
    fn roll_back(&self, prepared: &Record, previous: Option<Record>) {
        let Ok(tx) = self.store.lock() else {
            eprintln!("{LOG}: could not roll back the prepared record — the state lock was busy");
            return;
        };
        let next = match &previous {
            Some(record) => Next::Record(record),
            None => Next::Cleared,
        };
        if let Err(error) = self
            .store
            .transition(&tx, Some(Expected::of(prepared)), next)
        {
            eprintln!("{LOG}: not rolling back — {error}");
        }
    }

    /// Hand off to a child running `tier` with no episode: nothing is prepared,
    /// nothing is claimed, and nothing is persisted. This is what a manual
    /// override is — a launch the ladder runs but does not learn from.
    fn force(&self, tier: usize) -> Handoff {
        match self.rung(tier) {
            Ok(rung) => {
                let tag = Tag {
                    episode: None,
                    profile: rung.name.to_string(),
                };
                self.spawn_child(rung, &tag, &Release::NothingHeld)
            }
            Err(refusal) => Handoff::RefusedBeforeRelease(refusal),
        }
    }

    /// The release boundary itself: every preflight that can fail runs *before*
    /// `release.run()`, and everything after it is reported as a post-release
    /// outcome.
    ///
    /// Resolving the binary belongs on this side of the line. Held as an
    /// unresolved `Result` and passed onward it would surface only inside the
    /// launcher — after the name was already gone — turning a plainly
    /// recoverable "cannot find my own executable" into a stranded app.
    fn spawn_child(&self, rung: &'static Tier, tag: &Tag, release: &Release<'_>) -> Handoff {
        let binary = match tauri::process::current_binary(&tauri::Env::default()) {
            Ok(binary) => binary,
            Err(error) => {
                return Handoff::RefusedBeforeRelease(Refusal::NoBinary(error.to_string()));
            }
        };

        let released = release.run();
        match (self.launch)(
            &self.dbus_name,
            &binary,
            &self.args,
            self.package,
            rung,
            tag,
        ) {
            Ok(pid) => {
                eprintln!("{LOG}: handed off to {} as pid {pid}", rung.name);
                Handoff::Launched
            }
            Err(refusal) => match released {
                true => Handoff::RefusedAfterRelease(refusal),
                false => Handoff::RefusedBeforeRelease(refusal),
            },
        }
    }
}
