use super::*;

fn task() -> DurableTaskCore {
    DurableTaskCore {
        schema_version: TASK_SCHEMA_VERSION.into(),
        task_id: "task-1".into(),
        revision: 1,
        previous_revision_hash: None,
        status: TaskStatus::Running,
        owner_pubkey: "owner".into(),
        actor_pubkey: "actor".into(),
        authority_grant_id: "grant".into(),
        authority_expires_at: "2030-01-01T00:00:00Z".into(),
        bindings: TaskBindings {
            policy_hash: "a".repeat(64),
            sandbox_profile_hash: "b".repeat(64),
            runtime_attestation_hash: "c".repeat(64),
            runtime_attestation_expires_at: "2030-01-01T00:00:00Z".into(),
            execution_locus: "local".into(),
        },
        budget: TaskBudget {
            token_limit: Some(100),
            cost_limit_microusd: Some(100),
            wall_deadline: None,
            consumed_tokens: 1,
            consumed_microusd: 1,
        },
        input_hashes: vec!["d".repeat(64)],
        artifact_hashes: vec!["e".repeat(64)],
        unresolved_blocking_decisions: Vec::new(),
    }
}

#[test]
fn effect_key_is_stable_and_unambiguous() {
    assert_eq!(
        logical_effect_key("a", "bc", "d"),
        logical_effect_key("a", "bc", "d")
    );
    assert_ne!(
        logical_effect_key("a", "bc", "d"),
        logical_effect_key("ab", "c", "d")
    );
}

#[test]
fn revision_requires_exact_previous_hash() {
    let previous = task();
    let mut next = previous.clone();
    next.revision += 1;
    next.status = TaskStatus::Waiting;
    assert!(validate_revision(&previous, &next).is_err());
    next.previous_revision_hash = Some(hex::encode(Sha256::digest(
        serde_json::to_vec(&previous).unwrap(),
    )));
    assert!(validate_revision(&previous, &next).is_ok());
}

#[test]
fn delivery_fails_closed() {
    let mut value = task();
    value.status = TaskStatus::ReadyForDelivery;
    assert!(value.validate_delivery(false).is_err());
    value
        .unresolved_blocking_decisions
        .push("owner-choice".into());
    assert!(value.validate_delivery(true).is_err());
    value.unresolved_blocking_decisions.clear();
    assert!(value.validate_delivery(true).is_ok());
}

#[test]
fn store_appends_by_compare_and_swap_and_survives_reopen() {
    let mut connection = Connection::open_in_memory().unwrap();
    let mut store = DurableTaskStore::new(&mut connection).unwrap();
    let first = task();
    let first_hash = store.create(&first).unwrap();

    let mut second = first.clone();
    second.revision = 2;
    second.status = TaskStatus::Waiting;
    second.previous_revision_hash = Some(first_hash.clone());
    let second_hash = store.compare_and_swap(&first_hash, &second).unwrap();
    let (loaded, loaded_hash) = store.load_head("task-1").unwrap().unwrap();
    assert_eq!(loaded, second);
    assert_eq!(loaded_hash, second_hash);
}

#[test]
fn store_rejects_duplicate_create_stale_writer_and_changed_payload_parent() {
    let mut connection = Connection::open_in_memory().unwrap();
    let mut store = DurableTaskStore::new(&mut connection).unwrap();
    let first = task();
    let first_hash = store.create(&first).unwrap();
    assert!(store.create(&first).is_err());

    let mut second = first.clone();
    second.revision = 2;
    second.status = TaskStatus::Waiting;
    second.previous_revision_hash = Some(first_hash.clone());
    store.compare_and_swap(&first_hash, &second).unwrap();

    let mut conflicting = second.clone();
    conflicting.revision = 3;
    conflicting.previous_revision_hash = Some("f".repeat(64));
    assert!(store.compare_and_swap(&first_hash, &conflicting).is_err());
}

#[test]
fn effect_journal_is_idempotent_and_rejects_payload_reuse() {
    let mut connection = Connection::open_in_memory().unwrap();
    let mut store = DurableTaskStore::new(&mut connection).unwrap();
    let prepared = store
        .prepare_effect("task-1", "step-1", "delivery", b"payload")
        .unwrap();
    assert_eq!(prepared.state, EffectState::Prepared);
    assert_eq!(
        store
            .prepare_effect("task-1", "step-1", "delivery", b"payload")
            .unwrap(),
        prepared
    );
    assert!(store
        .prepare_effect("task-1", "step-1", "delivery", b"changed")
        .unwrap_err()
        .contains("different payload"));
}

#[test]
fn effect_receipt_is_recorded_exactly_once() {
    let mut connection = Connection::open_in_memory().unwrap();
    let mut store = DurableTaskStore::new(&mut connection).unwrap();
    let prepared = store
        .prepare_effect("task-1", "step-1", "delivery", b"payload")
        .unwrap();
    let pending = store.mark_effect_pending(&prepared.effect_key).unwrap();
    assert_eq!(pending.state, EffectState::Pending);
    let observed = store
        .observe_effect(&prepared.effect_key, b"receipt")
        .unwrap();
    assert_eq!(observed.state, EffectState::Observed);
    assert_eq!(
        store
            .observe_effect(&prepared.effect_key, b"receipt")
            .unwrap(),
        observed
    );
    assert!(store
        .observe_effect(&prepared.effect_key, b"other receipt")
        .is_err());
}

#[test]
fn indeterminate_effect_cannot_be_blindly_retried() {
    let mut connection = Connection::open_in_memory().unwrap();
    let mut store = DurableTaskStore::new(&mut connection).unwrap();
    let prepared = store
        .prepare_effect("task-1", "step-1", "delivery", b"payload")
        .unwrap();
    store.mark_effect_pending(&prepared.effect_key).unwrap();
    let waiting = store
        .mark_effect_indeterminate(&prepared.effect_key)
        .unwrap();
    assert_eq!(waiting.state, EffectState::Indeterminate);
    assert!(store.mark_effect_pending(&prepared.effect_key).is_err());
    assert!(store
        .observe_effect(&prepared.effect_key, b"unproven")
        .is_err());
}

#[test]
fn lease_recovery_increments_generation_and_fences_stale_holder() {
    let mut connection = Connection::open_in_memory().unwrap();
    let mut store = DurableTaskStore::new(&mut connection).unwrap();
    store.create(&task()).unwrap();
    let now = "2029-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let first = store
        .acquire_lease("task-1", "worker-a", "2029-01-01T00:01:00Z", now)
        .unwrap();
    assert_eq!(first.generation, 1);
    assert!(store
        .acquire_lease("task-1", "worker-b", "2029-01-01T00:02:00Z", now)
        .is_err());

    let recovered_at = "2029-01-01T00:01:00Z".parse::<DateTime<Utc>>().unwrap();
    let second = store
        .acquire_lease("task-1", "worker-b", "2029-01-01T00:03:00Z", recovered_at)
        .unwrap();
    assert_eq!(second.generation, 2);
    assert!(store
        .renew_lease(&first, "2029-01-01T00:04:00Z", recovered_at)
        .is_err());
    assert!(store
        .renew_lease(&second, "2029-01-01T00:04:00Z", recovered_at)
        .is_ok());
}

#[test]
fn handoff_acceptance_requires_new_recipient_grant_and_wins_once() {
    let mut connection = Connection::open_in_memory().unwrap();
    let mut store = DurableTaskStore::new(&mut connection).unwrap();
    let first = task();
    let first_hash = store.create(&first).unwrap();
    let now = "2029-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let handoff = store
        .create_handoff(
            "task-1",
            &first_hash,
            "recipient",
            "review-artifact",
            "2029-01-01T01:00:00Z",
            now,
        )
        .unwrap();
    let losing_handoff = store
        .create_handoff(
            "task-1",
            &first_hash,
            "other-recipient",
            "review-artifact",
            "2029-01-01T01:00:00Z",
            now,
        )
        .unwrap();

    let mut next = first.clone();
    next.revision = 2;
    next.previous_revision_hash = Some(first_hash);
    next.actor_pubkey = "recipient".into();
    next.authority_grant_id = "recipient-grant".into();
    let accepted_hash = store
        .accept_handoff(&handoff.handoff_id, "recipient", &next, now)
        .unwrap();
    assert_eq!(store.load_head("task-1").unwrap().unwrap().1, accepted_hash);
    assert!(store
        .accept_handoff(&handoff.handoff_id, "recipient", &next, now)
        .is_err());

    let mut losing_next = next.clone();
    losing_next.actor_pubkey = "other-recipient".into();
    losing_next.authority_grant_id = "other-grant".into();
    assert!(store
        .accept_handoff(
            &losing_handoff.handoff_id,
            "other-recipient",
            &losing_next,
            now,
        )
        .unwrap_err()
        .contains("revision race"));
}

fn snapshot(value: &DurableTaskCore) -> RevalidationSnapshot {
    RevalidationSnapshot {
        owner_pubkey: value.owner_pubkey.clone(),
        actor_pubkey: value.actor_pubkey.clone(),
        authority_grant_id: value.authority_grant_id.clone(),
        authority_active: true,
        policy_hash: value.bindings.policy_hash.clone(),
        sandbox_profile_hash: value.bindings.sandbox_profile_hash.clone(),
        runtime_attestation_hash: value.bindings.runtime_attestation_hash.clone(),
        execution_locus: value.bindings.execution_locus.clone(),
        input_hashes: value.input_hashes.clone(),
        artifact_hashes: value.artifact_hashes.clone(),
    }
}

#[test]
fn pre_effect_gate_accepts_only_exact_live_bindings() {
    let value = task();
    let now = "2029-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    assert_eq!(
        value.revalidate_before_effect(&snapshot(&value), now),
        Ok(())
    );

    let mut drifted = snapshot(&value);
    drifted.policy_hash = "f".repeat(64);
    assert_eq!(
        value.revalidate_before_effect(&drifted, now),
        Err(RevalidationFailure::Policy)
    );
    drifted = snapshot(&value);
    drifted.input_hashes[0] = "f".repeat(64);
    assert_eq!(
        value.revalidate_before_effect(&drifted, now),
        Err(RevalidationFailure::Inputs)
    );
}

#[test]
fn pre_effect_gate_fails_closed_on_expiry_and_exhausted_budget() {
    let value = task();
    let expired_now = "2030-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    assert_eq!(
        value.revalidate_before_effect(&snapshot(&value), expired_now),
        Err(RevalidationFailure::Authority)
    );

    let mut exhausted = task();
    exhausted.budget.consumed_tokens = 100;
    let valid_now = "2029-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    assert_eq!(
        exhausted.revalidate_before_effect(&snapshot(&exhausted), valid_now),
        Err(RevalidationFailure::TokenBudget)
    );
}
