//! Durable transitions under real contention, and the rules that make a late
//! writer harmless.
//!
//! The exclusive claim only serializes the creation of one claim file, so these
//! drive the transitions themselves from two threads through a barrier with the
//! state lock held across the window each race needs.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use super::*;

// ── Serialized transitions under real contention ────────────────────────────
//
// The exclusive claim only serializes the creation of one claim file. These
// tests drive the transitions themselves from two threads through a barrier,
// with the state lock held across the window the race needs, so the ordering is
// forced rather than hoped for.
//
// `flock` is per-open-file-description, so two `Store` values in one process
// contend exactly as two processes would — verified by the blocking assertions
// below, which only hold if the second writer really waits.

/// Give a thread parked on the state lock time to get there. Only the
/// *contention* evidence depends on this interval; every invariant assertion is
/// ordering-based and holds however the sleep lands.
const CONTENTION_WINDOW: std::time::Duration = std::time::Duration::from_millis(150);

#[test]
fn test_a_stale_generation_cannot_overwrite_a_record_prepared_while_it_waited() {
    // The interleaving Thufir named: a delayed generation-0 child is mid-claim
    // when another invocation durably prepares generation 1. Split into three
    // unsynchronized operations the child would read gen 0 as current, pause,
    // and then stamp its stale `started` over the newer record.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::new(dir.path());
    store.seed_record(&record(Phase::Prepared, 0, 1));

    // Held for the whole window in which the stale child is trying to claim.
    let tx = store.lock().expect("lock");

    let path = dir.path().to_path_buf();
    let arrived = Arc::new(Barrier::new(2));
    let finished = Arc::new(AtomicBool::new(false));
    let stale = {
        let (arrived, finished) = (Arc::clone(&arrived), Arc::clone(&finished));
        std::thread::spawn(move || {
            let store = Store::new(&path);
            arrived.wait();
            let claimed = claim(
                &store,
                &Episode {
                    token: TOKEN.to_string(),
                    generation: 0,
                },
            );
            finished.store(true, Ordering::SeqCst);
            claimed
        })
    };

    arrived.wait();
    std::thread::sleep(CONTENTION_WINDOW);
    assert!(
        !finished.load(Ordering::SeqCst),
        "the claim must block on the state lock, not proceed beside the holder"
    );

    // The retry becomes durable while the stale child is parked.
    let prepared = record(Phase::Prepared, 1, 1);
    let current = store.read().expect("the generation-0 record");
    store
        .transition(&tx, Some(Expected::of(&current)), Next::Record(&prepared))
        .expect("prepare generation 1");
    drop(tx);

    let claimed = stale.join().expect("stale child");
    // Only reachable if the child read the record *after* the write above, which
    // is the serialization this test exists to prove.
    assert!(
        matches!(claimed, Claimed::Superseded(_)),
        "a generation-0 child must be turned away once generation 1 is current"
    );
    assert_eq!(store.read().as_ref(), Some(&prepared));
    assert_eq!(store.claim_count(), 0);
}

#[test]
fn test_a_confirmation_racing_a_handoff_does_not_resurrect_its_episode() {
    // `note_confirmed` runs from the startup-boundary thread, so it can be in
    // flight when a crash handoff has already prepared the next token. Writing
    // the old episode's `confirmed` over that token would make the ladder reuse
    // a profile the crash just disproved.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::new(dir.path());
    store.seed_record(&record(Phase::Prepared, 0, 1));
    let env = env_from(&[
        ("WEBKIT_DMABUF_RENDERER_FORCE_SHM", "1"),
        (PROFILE, "shm-transport"),
        (EPISODE, TOKEN),
        (GENERATION, "0"),
    ]);
    let Boot::Run(session) = reconcile(
        Ok(dir.path().to_path_buf()),
        IDENTIFIER,
        VERSION,
        Vec::new(),
        &env,
        accept,
    ) else {
        panic!("the tagged child claims its episode");
    };
    session.note_owned();
    assert_eq!(store.read().expect("record").phase, Phase::Owned);

    let tx = store.lock().expect("lock");

    let arrived = Arc::new(Barrier::new(2));
    let finished = Arc::new(AtomicBool::new(false));
    let confirming = {
        let (session, arrived, finished) = (
            Arc::clone(&session),
            Arc::clone(&arrived),
            Arc::clone(&finished),
        );
        std::thread::spawn(move || {
            arrived.wait();
            session.note_confirmed();
            finished.store(true, Ordering::SeqCst);
        })
    };

    arrived.wait();
    std::thread::sleep(CONTENTION_WINDOW);
    assert!(
        !finished.load(Ordering::SeqCst),
        "the confirmation must block on the state lock"
    );

    // What the crash handoff writes: a new token at the next rung.
    let handed_off = Record::new(
        Phase::Prepared,
        "a-newer-token",
        0,
        "cpu-raster",
        2,
        VERSION,
    );
    let current = store.read().expect("the owned record");
    store
        .transition(&tx, Some(Expected::of(&current)), Next::Record(&handed_off))
        .expect("prepare the next rung");
    drop(tx);

    confirming.join().expect("confirming thread");
    assert_eq!(
        store.read().as_ref(),
        Some(&handed_off),
        "the superseded episode's confirmation must be rejected, not written"
    );
}

/// Spawn counter for the two-callback race below. A `static` because the launch
/// edge is a plain fn pointer with no captured state; only that one test reads
/// it, so no other test can perturb the count.
static SPAWNS: AtomicUsize = AtomicUsize::new(0);

fn count_spawns(
    _name: &str,
    _binary: &std::path::Path,
    _args: &[OsString],
    _package: Package,
    _tier: &'static Tier,
    _tag: &Tag,
) -> Result<u32, Refusal> {
    Ok(SPAWNS.fetch_add(1, Ordering::SeqCst) as u32 + 1)
}

#[test]
fn test_two_termination_callbacks_hand_off_exactly_once() {
    // WebKit can report a second termination while the first handoff is in
    // flight. Two handoffs would spawn two children for two episodes — two live
    // Buzz processes racing one name, with the record naming only one of them.
    SPAWNS.store(0, Ordering::SeqCst);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::new(dir.path());
    let env = env_from(&[]);
    let Boot::Run(session) = reconcile(
        Ok(dir.path().to_path_buf()),
        IDENTIFIER,
        VERSION,
        Vec::new(),
        &env,
        count_spawns,
    ) else {
        panic!("a first launch runs tier 0 here");
    };

    let arrived = Arc::new(Barrier::new(2));
    let callbacks: Vec<_> = (0..2)
        .map(|_| {
            let (session, arrived) = (Arc::clone(&session), Arc::clone(&arrived));
            std::thread::spawn(move || {
                arrived.wait();
                matches!(
                    session.on_web_process_terminated(Termination::Crashed, &|| {}),
                    CrashResponse::HandedOff
                )
            })
        })
        .collect();

    let handed_off = callbacks
        .into_iter()
        .map(|thread| thread.join().expect("callback"))
        .filter(|handed| *handed)
        .count();

    assert_eq!(handed_off, 1, "exactly one callback may hand off");
    assert_eq!(
        SPAWNS.load(Ordering::SeqCst),
        1,
        "exactly one child may be spawned"
    );
    // One survivor, and the durable record names the episode it was spawned for.
    let prepared = store.read().expect("the survivor's record");
    assert_eq!(prepared.phase, Phase::Prepared);
    assert_eq!(prepared.tier, 1);
    assert_eq!(prepared.generation, 0);
    assert_eq!(store.claim_count(), 0);
}

/// Where a racing launch edge finds the store to act on.
///
/// The launch edge is a bare `fn` pointer and captures nothing, so the path has
/// to reach it through a `static`. Each racing edge therefore gets its OWN
/// `static` rather than sharing one: two tests using the same slot overwrite
/// each other's path when the harness runs them in parallel, which is a race in
/// the test scaffolding rather than in the code under test.
static ROLLBACK_STORE: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);
static RESET_STORE: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// The competing record: a different episode, prepared by "another launch"
/// during the spawn window, then refused so the parent reaches its rollback.
fn refuse_after_a_competing_prepare(
    _name: &str,
    _binary: &std::path::Path,
    _args: &[OsString],
    _package: Package,
    _tier: &'static Tier,
    _tag: &Tag,
) -> Result<u32, Refusal> {
    let path = ROLLBACK_STORE.lock().expect("path").clone().expect("path");
    Store::new(&path).seed_record(&Record::new(
        Phase::Prepared,
        "a-newer-token",
        0,
        "cpu-raster",
        2,
        VERSION,
    ));
    Err(Refusal::SpawnFailed("no child".to_string()))
}

#[test]
fn test_a_rollback_does_not_erase_an_episode_prepared_after_it() {
    // The state lock is dropped between the prepared write and the spawn, which
    // is deliberate — the spawn must not run under it. So a refusal can come
    // back after another launch has prepared its own episode, and an unchecked
    // rollback would delete a record that launch's child is about to claim,
    // turning a real handoff into an untracked launch.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::new(dir.path());
    store.seed_record(&record(Phase::Confirmed, 0, 2));
    *ROLLBACK_STORE.lock().expect("path") = Some(dir.path().to_path_buf());
    let env = env_from(&[]);

    // Wants tier 2, so it prepares a record, spawns, and is refused.
    let boot = reconcile(
        Ok(dir.path().to_path_buf()),
        IDENTIFIER,
        VERSION,
        Vec::new(),
        &env,
        refuse_after_a_competing_prepare,
    );

    assert!(matches!(boot, Boot::Run(_)), "a refusal keeps this process");
    let current = store.read().expect("the competing episode's record");
    assert_eq!(
        current.token, "a-newer-token",
        "the rollback must leave the newer episode alone"
    );
    assert_eq!(current.phase, Phase::Prepared);
}

// ── Stale boot decisions ────────────────────────────────────────────────────
//
// Deciding and writing are two steps with a D-Bus round trip between them, so
// the record can move in between. These prove the write is refused rather than
// applied, and that the launch then re-decides from what is actually there.

/// A refusing launch edge that clears the state dir first, standing in for
/// another process running `--reset-rendering-mode` inside the window between
/// this launch's classification and its prepared write.
///
/// Refusing after the clear is what keeps the test honest: the parent reaches
/// its rollback, so a rollback that ignored the reset would restore the record
/// just as surely as a stale prepare would.
fn reset_then_refuse(
    _name: &str,
    _binary: &std::path::Path,
    _args: &[OsString],
    _package: Package,
    _tier: &'static Tier,
    _tag: &Tag,
) -> Result<u32, Refusal> {
    let path = RESET_STORE.lock().expect("path").clone().expect("path");
    let store = Store::new(&path);
    let tx = store.lock().expect("lock");
    let current = store.read();
    store
        .transition(&tx, current.as_ref().map(Expected::of), Next::Cleared)
        .expect("reset");
    Err(Refusal::SpawnFailed("no child".to_string()))
}

#[test]
fn test_a_reset_is_not_undone_by_a_launch_that_decided_before_it() {
    // The race Thufir named: A reads a failed tier and decides to advance, B
    // resets and reports success, then A writes its pre-reset decision. If A's
    // write lands, the user who just cleared their renderer state finds a
    // prepared episode waiting for them anyway.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::new(dir.path());
    store.seed_record(&record(Phase::Confirmed, 0, 2));
    *RESET_STORE.lock().expect("path") = Some(dir.path().to_path_buf());
    let env = env_from(&[]);

    let boot = reconcile(
        Ok(dir.path().to_path_buf()),
        IDENTIFIER,
        VERSION,
        Vec::new(),
        &env,
        reset_then_refuse,
    );

    // The app still starts — a reset is not a reason to refuse to launch — but
    // at the baseline it was launched as, with nothing persisted.
    let Boot::Run(session) = boot else {
        panic!("a cleared record still starts the app");
    };
    assert_eq!(session.profile_name(), "full-gpu");
    assert_eq!(
        store.read(),
        None,
        "the reset must survive the decision taken before it"
    );
}

#[test]
fn test_a_version_mismatch_discard_does_not_delete_a_newer_episode() {
    // The mirror race: this launch classifies a record from another app version
    // and decides to discard it, but by the time it writes, a current-version
    // launch has prepared an episode whose child is about to claim it. A blind
    // clear would turn that handoff into an untracked launch.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::new(dir.path());
    let stale_version = Record::new(Phase::Confirmed, TOKEN, 0, "cpu-raster", 2, "0.4.25");
    store.seed_record(&stale_version);

    // Classify the old record exactly as `reconcile` does, then let the newer
    // episode land before the discard is attempted.
    let classified = store.read().expect("the other version's record");
    let newer = Record::new(
        Phase::Prepared,
        "a-newer-token",
        0,
        "shm-transport",
        1,
        VERSION,
    );
    store.seed_record(&newer);

    let tx = store.lock().expect("lock");
    let refused = store
        .transition(&tx, Some(Expected::of(&classified)), Next::Cleared)
        .is_err();
    drop(tx);

    assert!(refused, "the discard must be refused, not applied");
    assert_eq!(
        store.read().as_ref(),
        Some(&newer),
        "the newer episode must survive a delayed discard"
    );
}

// ── The exact receipt chain ─────────────────────────────────────────────────
//
// A receipt names the phase it follows, so the chain is checked by the same
// comparison that rejects a superseded episode. These drive the real store
// rather than a predicate, which is what makes them evidence that nothing lands
// on disk.

/// Attempt a receipt exactly as `Session::note` does — expecting this episode at
/// the phase `next` must follow — and report whether it landed.
fn receipt(store: &Store, episode: &Episode, next: Phase) -> bool {
    let follows = predecessor_of(next).expect("a receipt phase has a predecessor");
    let mut written = record(next, episode.generation, 1);
    written.pid = Some(std::process::id());
    let tx = store.lock().expect("lock");
    store
        .transition(
            &tx,
            Some(Expected::after(&episode.token, episode.generation, follows)),
            Next::Record(&written),
        )
        .is_ok()
}

fn episode_zero() -> Episode {
    Episode {
        token: TOKEN.to_string(),
        generation: 0,
    }
}

#[test]
fn test_the_receipt_chain_admits_only_the_exact_next_phase() {
    let (_dir, store) = store();
    store.seed_record(&record(Phase::Started, 0, 1));
    let episode = episode_zero();

    // Backwards and sideways: a repeated callback has nothing to add, and an
    // out-of-order one must not undo a later phase.
    assert!(!receipt(&store, &episode, Phase::Started));
    // The one legal move from `started`.
    assert!(receipt(&store, &episode, Phase::Owned));
    assert_eq!(store.read().expect("record").phase, Phase::Owned);
    assert!(receipt(&store, &episode, Phase::Confirmed));
    assert_eq!(store.read().expect("record").phase, Phase::Confirmed);
}

#[test]
fn test_a_receipt_that_skips_its_predecessor_is_rejected() {
    // Rank-based "forward" accepted these. The chain is exact: a `confirmed`
    // that skips `owned` would persist a crash-free startup fact for a tier that
    // never recorded holding the name, and the next launch would reuse it.
    for (from, skipped) in [
        (Phase::Prepared, Phase::Owned),
        (Phase::Prepared, Phase::Confirmed),
        (Phase::Started, Phase::Confirmed),
    ] {
        let (_dir, store) = store();
        let before = record(from, 0, 1);
        store.seed_record(&before);

        assert!(
            !receipt(&store, &episode_zero(), skipped),
            "{skipped:?} must not be writable over {from:?}"
        );
        assert_eq!(
            store.read().as_ref(),
            Some(&before),
            "a rejected receipt must leave the record untouched"
        );
    }
}

#[test]
fn test_a_receipt_for_a_superseded_episode_is_rejected() {
    let (_dir, store) = store();
    store.seed_record(&record(Phase::Started, 0, 1));

    // Another token, and another generation of this token: neither is current.
    for episode in [
        Episode {
            token: "another-token".to_string(),
            generation: 0,
        },
        Episode {
            token: TOKEN.to_string(),
            generation: 1,
        },
    ] {
        assert!(!receipt(&store, &episode, Phase::Owned));
    }
    assert_eq!(store.read().expect("record").phase, Phase::Started);
}

#[test]
fn test_a_receipt_does_not_recreate_a_cleared_record() {
    // The record a receipt belongs to is written by the parent before the child
    // exists, so its absence means the episode was cleared — not that a receipt
    // should bring it back.
    let (_dir, store) = store();
    assert!(!receipt(&store, &episode_zero(), Phase::Owned));
    assert_eq!(store.read(), None);
}

#[test]
fn test_the_exhausted_phase_is_terminal_against_a_late_receipt() {
    // `exhausted` is written from any phase of its own attempt, so nothing in
    // the chain leads out of it: every receipt names a predecessor, and
    // `exhausted` is not one.
    let (_dir, store) = store();
    let exhausted = record(Phase::Exhausted, 0, 3);
    store.seed_record(&exhausted);
    let episode = episode_zero();

    for phase in [Phase::Started, Phase::Owned, Phase::Confirmed] {
        assert!(!receipt(&store, &episode, phase));
    }
    assert_eq!(store.read().as_ref(), Some(&exhausted));
}

#[test]
fn test_only_prepared_and_exhausted_have_no_predecessor() {
    // The two phases no receipt writes: `prepared` is written by a parent about
    // an attempt that does not exist yet, and `exhausted` is validated against
    // the whole attempt instead of one position.
    assert_eq!(predecessor_of(Phase::Started), Some(Phase::Prepared));
    assert_eq!(predecessor_of(Phase::Owned), Some(Phase::Started));
    assert_eq!(predecessor_of(Phase::Confirmed), Some(Phase::Owned));
    assert_eq!(predecessor_of(Phase::Prepared), None);
    assert_eq!(predecessor_of(Phase::Exhausted), None);
}
