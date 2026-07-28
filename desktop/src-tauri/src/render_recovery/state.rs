//! Durable episode state: the `prepared → started → owned → confirmed` record
//! and the exclusive `(token, generation)` claim.
//!
//! Phases are monotonic and each post-parent phase records the identity that
//! makes the episode verifiable — a pid, then the D-Bus unique name and bus id.
//! Only the child that wins the exclusive claim ever writes a receipt.
//!
//! Claims are keyed on `(token, generation)` rather than the token alone. The
//! sole retry reuses the same token, and an exclusive claim is one-shot by
//! design, so a token-only key would make the retry lose its own claim against
//! the first attempt's file. Claim files are never deleted: a stale claim is
//! inert evidence that a generation already ran, and deleting one cannot be
//! fused with the record write into a single durable step.
//!
//! An exclusive claim only serializes the creation of one claim file, which is
//! not enough on its own: reading the record, deciding from it, and writing the
//! next phase are three operations, and a writer descheduled between them could
//! stamp a stale phase onto a newer episode. So [`Store::transition`] is the
//! only way to make anything durable, and it is compare-and-transition: it
//! re-reads the record under the caller's [`Transaction`] and applies the write
//! only if the record still exactly matches the one the caller decided from.
//! The lock orders writers; the comparison is what makes a delayed writer
//! harmless.
//!
//! Because the expected source names a *phase* and not merely an identity, the
//! chain is exact for free: a caller writing `owned` declares that it expects
//! `started`, so `prepared → owned` is rejected as a mismatch with no separate
//! ordering rule to keep in step with the phase list.

use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

/// Where the record and claim files live, relative to the app data dir.
const DIR: &str = "render-recovery";
const RECORD: &str = "episode.json";
const CLAIMS: &str = "claims";
/// The transaction lock, a **sibling** of `DIR` rather than a child: `clear()`
/// removes `DIR` wholesale, and a lock inode inside it would be unlinked from
/// under a concurrent holder — leaving two processes each holding a "lock" on a
/// different inode.
const LOCK: &str = "render-recovery.lock";

/// The sole retry generation. An attempt whose child never claimed is retried
/// exactly once, under generation 1; there is no generation 2.
pub(crate) const RETRY_GENERATION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Phase {
    /// Written by the parent, atomically, before spawning.
    Prepared,
    /// Written by the exclusively claiming child as its first action.
    Started,
    /// Written by the same child once it holds the single-instance name.
    Owned,
    /// Written by the same child once the startup boundary passes. Doubles as
    /// the persisted "last crash-free startup profile" fact.
    Confirmed,
    /// The ladder ran out of rungs for this package. Terminal.
    Exhausted,
}

/// The durable record. One file, rewritten atomically at each transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Record {
    pub phase: Phase,
    /// Attempt identity. A new rung mints a new token; the retry reuses it.
    pub token: String,
    /// Retry identity within the attempt: 0, and `RETRY_GENERATION` for the
    /// sole retry.
    pub generation: u32,
    /// Tier name, e.g. `shm-transport`. Recorded for the log; the tier index
    /// is what the ladder actually reads.
    pub profile: String,
    /// Tier index into the package's ladder.
    pub tier: usize,
    /// App version, so a persisted profile does not survive an upgrade.
    pub version: String,
    /// The claiming child's pid. Present from `started` onward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// The child's D-Bus unique name. Present from `owned` onward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_name: Option<String>,
    /// The bus the unique name was issued on. A unique name is only meaningful
    /// against the bus that minted it; a different bus can reuse `:1.4`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus_id: Option<String>,
}

impl Record {
    pub(crate) fn new(
        phase: Phase,
        token: &str,
        generation: u32,
        profile: &str,
        tier: usize,
        version: &str,
    ) -> Self {
        Record {
            phase,
            token: token.to_string(),
            generation,
            profile: profile.to_string(),
            tier,
            version: version.to_string(),
            pid: None,
            unique_name: None,
            bus_id: None,
        }
    }
}

/// The record state a transition requires *before* it writes anything.
///
/// Every mutation names the state its caller decided from and is refused if the
/// record has moved since. The comparison is on `(token, generation)` plus
/// optionally the phase; pid, owner identity, and tier are payload a transition
/// records rather than depends on.
///
/// `phase: Some(_)` is what makes the receipt chain exact. A receipt is written
/// with the phase it must follow — `owned` expects `started` — so a skip is an
/// ordinary mismatch, and there is no separate ordering rule that could drift
/// out of step with the phase list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Expected<'a> {
    token: &'a str,
    generation: u32,
    /// `None` matches this attempt at any phase.
    phase: Option<Phase>,
}

impl<'a> Expected<'a> {
    /// Exactly the record the caller has in hand, phase included. What a
    /// decision taken from an earlier read must prove is still current.
    pub(crate) fn of(record: &'a Record) -> Self {
        Expected {
            token: &record.token,
            generation: record.generation,
            phase: Some(record.phase),
        }
    }

    /// This attempt at exactly `phase`. Used by receipts, which name the phase
    /// they follow rather than holding the record that carries it.
    pub(crate) fn after(token: &'a str, generation: u32, phase: Phase) -> Self {
        Expected {
            token,
            generation,
            phase: Some(phase),
        }
    }

    /// This attempt wherever the chain has reached.
    ///
    /// For a live process writing about its own episode: it is the only writer
    /// of that episode's receipts, so any phase of it is a legitimate source,
    /// and what must still be caught — a reset, or a newer episode — changes the
    /// token or clears the record either way.
    pub(crate) fn attempt(token: &'a str, generation: u32) -> Self {
        Expected {
            token,
            generation,
            phase: None,
        }
    }

    fn holds(&self, current: Option<&Record>) -> bool {
        current.is_some_and(|current| {
            current.token == self.token
                && current.generation == self.generation
                && self.phase.is_none_or(|phase| current.phase == phase)
        })
    }
}

/// What a transition makes durable.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Next<'a> {
    /// Replace the record with this one.
    Record(&'a Record),
    /// Delete the record and every claim. `--reset-rendering-mode`, and the
    /// discard of a record written by another app version.
    Cleared,
}

/// Why a transition did not happen.
///
/// Both variants carry a description rather than the record involved: every
/// caller either reports the refusal or re-decides from a fresh read, and none
/// inspects the record that was found.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The record is no longer the one the caller decided from, so whatever the
    /// caller intended rests on state that no longer exists. The caller must
    /// reconcile again rather than proceed.
    Stale(String),
    /// The record could not be made durable.
    NotDurable(String),
}

impl Refused {
    /// Describe what was found where the caller expected its own source.
    fn stale(found: Option<&Record>) -> Self {
        Refused::Stale(match found {
            Some(found) => format!(
                "the episode record is now {:?} (token={} gen={})",
                found.phase, found.token, found.generation
            ),
            None => "the episode record was cleared".to_string(),
        })
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Stale(detail) => f.write_str(detail),
            Refused::NotDurable(error) => write!(f, "the record is not durable: {error}"),
        }
    }
}

/// Filesystem home of the episode record and its claim files.
pub(crate) struct Store {
    dir: PathBuf,
    lock: PathBuf,
}

/// Proof that the caller holds the cross-process transaction lock.
///
/// Every mutation of the record takes one of these by reference, so a
/// read-validate-write sequence cannot be written without serializing it. The
/// lock is released when this value drops, and also — the property a lockfile
/// alone cannot offer — when the holding process dies, since the kernel closes
/// its descriptors. A crashing parent therefore never wedges the ladder.
pub(crate) struct Transaction {
    _file: std::fs::File,
}

/// Outcome of an exclusive claim attempt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Claim {
    /// This process owns the transition and must write the receipt.
    Won,
    /// Another process holds this `(token, generation)`. Write nothing.
    Lost,
    /// The claim could not be attempted. Also write nothing — a claim that
    /// cannot be proven exclusive is not a claim.
    Failed(String),
}

impl Store {
    pub(crate) fn new(app_data_dir: &Path) -> Self {
        Store {
            dir: app_data_dir.join(DIR),
            lock: app_data_dir.join(LOCK),
        }
    }

    /// Serialize every writer of this store against each other.
    ///
    /// `flock` rather than an `O_EXCL` lockfile because it is released by the
    /// kernel on process death: a lockfile left behind by a process that
    /// crashed mid-transition — exactly the failure this feature exists to
    /// handle — would need a liveness heuristic to break, and a wrong guess
    /// there either wedges recovery forever or defeats the mutual exclusion.
    pub(crate) fn lock(&self) -> Result<Transaction, String> {
        if let Some(parent) = self.lock.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock)
            .map_err(|e| format!("open {}: {e}", self.lock.display()))?;
        // Blocking: the critical sections are one small file write each, and a
        // caller that gave up on the lock would have to either skip its
        // transition or race it — both worse than waiting.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(format!(
                "lock {}: {}",
                self.lock.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(Transaction { _file: file })
    }

    fn record_path(&self) -> PathBuf {
        self.dir.join(RECORD)
    }

    fn claim_path(&self, token: &str, generation: u32) -> PathBuf {
        self.dir.join(CLAIMS).join(format!("{token}-g{generation}"))
    }

    /// Read the record. An unreadable or unparsable record is `None` — the
    /// caller treats that as absent and starts from the baseline.
    pub(crate) fn read(&self) -> Option<Record> {
        let text = std::fs::read_to_string(self.record_path()).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Atomically replace the record, or delete it, if the record still matches
    /// `expected` — `None` meaning it must still be absent.
    ///
    /// This is the only way anything durable changes. The re-read happens under
    /// the caller's `Transaction`, so between the comparison and the write no
    /// other process can intervene — which is exactly what a caller that decided
    /// from an earlier read needs, since its decision may have been overtaken by
    /// a reset or a newer episode in the meantime.
    ///
    /// Durability matters for the write: a torn record after a crash would be
    /// indistinguishable from a corrupt one and would silently restart the
    /// ladder.
    pub(crate) fn transition(
        &self,
        _tx: &Transaction,
        expected: Option<Expected<'_>>,
        next: Next<'_>,
    ) -> Result<(), Refused> {
        let current = self.read();
        let holds = match expected {
            Some(expected) => expected.holds(current.as_ref()),
            None => current.is_none(),
        };
        if !holds {
            return Err(Refused::stale(current.as_ref()));
        }
        match next {
            Next::Cleared => {
                let _ = std::fs::remove_dir_all(&self.dir);
                Ok(())
            }
            Next::Record(record) => self.write(record).map_err(Refused::NotDurable),
        }
    }

    fn write(&self, record: &Record) -> Result<(), String> {
        use atomic_write_file::AtomicWriteFile;

        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("create {}: {e}", self.dir.display()))?;
        let path = self.record_path();
        let json = serde_json::to_vec_pretty(record).map_err(|e| format!("encode record: {e}"))?;
        let mut file =
            AtomicWriteFile::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
        file.write_all(&json)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        file.commit()
            .map_err(|e| format!("commit {}: {e}", path.display()))
    }

    /// Whether any renderer state exists, for `--reset-rendering-mode`'s report
    /// of what it cleared. Called under the same transaction as the clear.
    pub(crate) fn exists(&self, _tx: &Transaction) -> bool {
        self.dir.exists()
    }

    /// Drop the claim files of superseded episodes, keeping every claim that
    /// belongs to `keep_token`.
    ///
    /// This is not the deletion the contract forbids. That rule protects the
    /// *current* token, whose sole retry must not be able to erase its own
    /// first attempt's evidence — hence the `(token, generation)` key and the
    /// filter here. A claim belonging to an older token can strand nothing: a
    /// delayed child of a superseded episode is turned away by the token check
    /// against the record long before it looks at a claim file. Without this
    /// the directory grows by one file per relaunch, forever.
    ///
    /// Called only *after* the new record is durable. Pruning first would, on a
    /// failed record write, leave the old record current with its claim
    /// evidence already gone — and an old child that had passed its record read
    /// could then re-create its claim and write a receipt over the record.
    pub(crate) fn prune_claims(&self, _tx: &Transaction, keep_token: &str) {
        let claims = self.dir.join(CLAIMS);
        let Ok(entries) = std::fs::read_dir(&claims) else {
            return;
        };
        let keep = format!("{keep_token}-g");
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().starts_with(&keep) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Take exclusive ownership of one `(token, generation)`.
    ///
    /// `create_new` is `O_EXCL` at the filesystem level: of N racing processes
    /// exactly one gets `Ok`. This is the compare-and-transition primitive —
    /// a read-then-rename would let two children both pass the read and the
    /// loser write the last receipt.
    pub(crate) fn claim(&self, _tx: &Transaction, token: &str, generation: u32) -> Claim {
        let path = self.claim_path(token, generation);
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Claim::Failed(format!("create {}: {e}", parent.display()));
            }
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                let _ = writeln!(file, "pid={}", std::process::id());
                Claim::Won
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Claim::Lost,
            Err(e) => Claim::Failed(format!("claim {}: {e}", path.display())),
        }
    }

    #[cfg(test)]
    pub(crate) fn record_path_for_test(&self) -> PathBuf {
        self.record_path()
    }

    #[cfg(test)]
    pub(crate) fn claim_count(&self) -> usize {
        std::fs::read_dir(self.dir.join(CLAIMS))
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn seed_claim(&self, token: &str, generation: u32) {
        let tx = self.lock().expect("lock");
        assert_eq!(self.claim(&tx, token, generation), Claim::Won);
    }

    /// Write a record outside a transition, for tests that need a starting
    /// state. Takes and drops its own lock, and expects whatever is there.
    #[cfg(test)]
    pub(crate) fn seed_record(&self, record: &Record) {
        let tx = self.lock().expect("lock");
        let current = self.read();
        self.transition(
            &tx,
            current.as_ref().map(Expected::of),
            Next::Record(record),
        )
        .expect("seed");
    }
}
