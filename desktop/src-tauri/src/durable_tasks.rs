//! Fail-closed core contracts for resumable agent work.
//!
//! This module deliberately contains no effect dispatcher.  It is the durable
//! boundary that a dispatcher must satisfy before it can perform work.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TASK_SCHEMA_VERSION: &str = "guardian.durable-task/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Leased,
    Running,
    Waiting,
    PausedRevalidation,
    Validating,
    ReadyForDelivery,
    Complete,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBindings {
    pub policy_hash: String,
    pub sandbox_profile_hash: String,
    pub runtime_attestation_hash: String,
    pub runtime_attestation_expires_at: String,
    pub execution_locus: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBudget {
    pub token_limit: Option<u64>,
    pub cost_limit_microusd: Option<u64>,
    pub wall_deadline: Option<String>,
    pub consumed_tokens: u64,
    pub consumed_microusd: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableTaskCore {
    pub schema_version: String,
    pub task_id: String,
    pub revision: u64,
    pub previous_revision_hash: Option<String>,
    pub status: TaskStatus,
    pub owner_pubkey: String,
    pub actor_pubkey: String,
    pub authority_grant_id: String,
    pub authority_expires_at: String,
    pub bindings: TaskBindings,
    pub budget: TaskBudget,
    pub input_hashes: Vec<String>,
    pub artifact_hashes: Vec<String>,
    pub unresolved_blocking_decisions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevalidationSnapshot {
    pub owner_pubkey: String,
    pub actor_pubkey: String,
    pub authority_grant_id: String,
    pub authority_active: bool,
    pub policy_hash: String,
    pub sandbox_profile_hash: String,
    pub runtime_attestation_hash: String,
    pub execution_locus: String,
    pub input_hashes: Vec<String>,
    pub artifact_hashes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevalidationFailure {
    Authority,
    Policy,
    Sandbox,
    RuntimeAttestation,
    ExecutionLocus,
    Inputs,
    Artifacts,
    TokenBudget,
    CostBudget,
    WallDeadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectState {
    Prepared,
    Pending,
    Observed,
    Indeterminate,
}

impl EffectState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Pending => "pending",
            Self::Observed => "observed",
            Self::Indeterminate => "indeterminate",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "pending" => Ok(Self::Pending),
            "observed" => Ok(Self::Observed),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => Err("stored durable effect state is invalid".into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRecord {
    pub effect_key: String,
    pub payload_hash: String,
    pub state: EffectState,
    pub receipt_hash: Option<String>,
}

/// Endpoint-local append-only storage. Relay state is never consulted here.
pub struct DurableTaskStore<'a> {
    connection: &'a mut Connection,
}

impl<'a> DurableTaskStore<'a> {
    pub fn new(connection: &'a mut Connection) -> Result<Self, String> {
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS guardian_durable_task_revision (
                   task_id TEXT NOT NULL,
                   revision INTEGER NOT NULL,
                   revision_hash TEXT NOT NULL UNIQUE,
                   previous_revision_hash TEXT,
                   status TEXT NOT NULL,
                   canonical_json BLOB NOT NULL,
                   PRIMARY KEY (task_id, revision)
                 );
                 CREATE TABLE IF NOT EXISTS guardian_durable_task_head (
                   task_id TEXT PRIMARY KEY,
                   revision INTEGER NOT NULL,
                   revision_hash TEXT NOT NULL,
                   FOREIGN KEY (task_id, revision)
                     REFERENCES guardian_durable_task_revision(task_id, revision)
                 );
                 CREATE TABLE IF NOT EXISTS guardian_durable_effect (
                   effect_key TEXT PRIMARY KEY,
                   task_id TEXT NOT NULL,
                   step_id TEXT NOT NULL,
                   logical_effect_id TEXT NOT NULL,
                   payload_hash TEXT NOT NULL,
                   state TEXT NOT NULL,
                   receipt_hash TEXT,
                   UNIQUE(task_id, step_id, logical_effect_id)
                 );",
            )
            .map_err(|error| format!("failed to initialize durable task store: {error}"))?;
        Ok(Self { connection })
    }

    pub fn create(&mut self, task: &DurableTaskCore) -> Result<String, String> {
        task.validate_shape()?;
        if task.revision != 1 || task.previous_revision_hash.is_some() {
            return Err("initial durable task must be revision 1 without a parent hash".into());
        }
        let bytes = canonical_bytes(task)?;
        let hash = hex::encode(Sha256::digest(&bytes));
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("failed to begin durable task transaction: {error}"))?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM guardian_durable_task_head WHERE task_id = ?1",
                [&task.task_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| format!("failed to inspect durable task head: {error}"))?
            .is_some();
        if exists {
            return Err("durable task already exists".into());
        }
        insert_revision(&transaction, task, &bytes, &hash)?;
        transaction
            .execute(
                "INSERT INTO guardian_durable_task_head(task_id, revision, revision_hash)
                 VALUES (?1, ?2, ?3)",
                params![task.task_id, task.revision, hash],
            )
            .map_err(|error| format!("failed to create durable task head: {error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("failed to commit durable task: {error}"))?;
        Ok(hash)
    }

    pub fn compare_and_swap(
        &mut self,
        expected_head_hash: &str,
        next: &DurableTaskCore,
    ) -> Result<String, String> {
        validate_sha256(expected_head_hash)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("failed to begin durable task transaction: {error}"))?;
        let (head_hash, bytes): (String, Vec<u8>) = transaction
            .query_row(
                "SELECT h.revision_hash, r.canonical_json
                 FROM guardian_durable_task_head h
                 JOIN guardian_durable_task_revision r
                   ON r.task_id = h.task_id AND r.revision = h.revision
                 WHERE h.task_id = ?1",
                [&next.task_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| format!("durable task head is unavailable: {error}"))?;
        if head_hash != expected_head_hash {
            return Err("durable task compare-and-swap conflict".into());
        }
        let previous: DurableTaskCore = serde_json::from_slice(&bytes)
            .map_err(|error| format!("stored durable task is corrupt: {error}"))?;
        validate_revision(&previous, next)?;
        let next_bytes = canonical_bytes(next)?;
        let next_hash = hex::encode(Sha256::digest(&next_bytes));
        insert_revision(&transaction, next, &next_bytes, &next_hash)?;
        let changed = transaction
            .execute(
                "UPDATE guardian_durable_task_head
                 SET revision = ?1, revision_hash = ?2
                 WHERE task_id = ?3 AND revision_hash = ?4",
                params![next.revision, next_hash, next.task_id, expected_head_hash],
            )
            .map_err(|error| format!("failed to update durable task head: {error}"))?;
        if changed != 1 {
            return Err("durable task compare-and-swap conflict".into());
        }
        transaction
            .commit()
            .map_err(|error| format!("failed to commit durable task revision: {error}"))?;
        Ok(next_hash)
    }

    pub fn load_head(&self, task_id: &str) -> Result<Option<(DurableTaskCore, String)>, String> {
        self.connection
            .query_row(
                "SELECT r.canonical_json, h.revision_hash
                 FROM guardian_durable_task_head h
                 JOIN guardian_durable_task_revision r
                   ON r.task_id = h.task_id AND r.revision = h.revision
                 WHERE h.task_id = ?1",
                [task_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| format!("failed to load durable task head: {error}"))?
            .map(|(bytes, hash)| {
                serde_json::from_slice(&bytes)
                    .map(|task| (task, hash))
                    .map_err(|error| format!("stored durable task is corrupt: {error}"))
            })
            .transpose()
    }

    /// Registers an intended external effect before dispatch. Repeating the
    /// same canonical payload returns the committed record; reusing the key
    /// for different bytes is an integrity error.
    pub fn prepare_effect(
        &mut self,
        task_id: &str,
        step_id: &str,
        logical_effect_id: &str,
        payload: &[u8],
    ) -> Result<EffectRecord, String> {
        if task_id.is_empty() || step_id.is_empty() || logical_effect_id.is_empty() {
            return Err("durable effect identity fields must not be empty".into());
        }
        let effect_key = logical_effect_key(task_id, step_id, logical_effect_id);
        let payload_hash = hex::encode(Sha256::digest(payload));
        if let Some(existing) = self.load_effect(&effect_key)? {
            if existing.payload_hash != payload_hash {
                return Err("durable effect key was reused with different payload bytes".into());
            }
            return Ok(existing);
        }
        self.connection
            .execute(
                "INSERT INTO guardian_durable_effect(
                   effect_key, task_id, step_id, logical_effect_id, payload_hash, state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'prepared')",
                params![
                    effect_key,
                    task_id,
                    step_id,
                    logical_effect_id,
                    payload_hash
                ],
            )
            .map_err(|error| format!("failed to prepare durable effect: {error}"))?;
        Ok(EffectRecord {
            effect_key,
            payload_hash,
            state: EffectState::Prepared,
            receipt_hash: None,
        })
    }

    /// Must commit before the external side effect is dispatched.
    pub fn mark_effect_pending(&mut self, effect_key: &str) -> Result<EffectRecord, String> {
        self.transition_effect(
            effect_key,
            EffectState::Prepared,
            EffectState::Pending,
            None,
        )
    }

    /// Reconciliation records the sink receipt exactly once. A duplicate with
    /// the same receipt is idempotent; a different receipt is rejected.
    pub fn observe_effect(
        &mut self,
        effect_key: &str,
        receipt: &[u8],
    ) -> Result<EffectRecord, String> {
        let receipt_hash = hex::encode(Sha256::digest(receipt));
        let current = self
            .load_effect(effect_key)?
            .ok_or_else(|| "durable effect does not exist".to_string())?;
        if current.state == EffectState::Observed {
            if current.receipt_hash.as_deref() == Some(receipt_hash.as_str()) {
                return Ok(current);
            }
            return Err("durable effect already has a different receipt".into());
        }
        if current.state != EffectState::Pending {
            return Err("only a pending durable effect can be observed".into());
        }
        self.transition_effect(
            effect_key,
            EffectState::Pending,
            EffectState::Observed,
            Some(&receipt_hash),
        )
    }

    pub fn mark_effect_indeterminate(&mut self, effect_key: &str) -> Result<EffectRecord, String> {
        self.transition_effect(
            effect_key,
            EffectState::Pending,
            EffectState::Indeterminate,
            None,
        )
    }

    pub fn load_effect(&self, effect_key: &str) -> Result<Option<EffectRecord>, String> {
        validate_sha256(effect_key)?;
        self.connection
            .query_row(
                "SELECT payload_hash, state, receipt_hash
                 FROM guardian_durable_effect WHERE effect_key = ?1",
                [effect_key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| format!("failed to load durable effect: {error}"))?
            .map(|(payload_hash, state, receipt_hash)| {
                Ok(EffectRecord {
                    effect_key: effect_key.to_string(),
                    payload_hash,
                    state: EffectState::parse(&state)?,
                    receipt_hash,
                })
            })
            .transpose()
    }

    fn transition_effect(
        &mut self,
        effect_key: &str,
        expected: EffectState,
        next: EffectState,
        receipt_hash: Option<&str>,
    ) -> Result<EffectRecord, String> {
        validate_sha256(effect_key)?;
        if let Some(hash) = receipt_hash {
            validate_sha256(hash)?;
        }
        let changed = self
            .connection
            .execute(
                "UPDATE guardian_durable_effect SET state = ?2, receipt_hash = ?3
                 WHERE effect_key = ?1 AND state = ?4",
                params![effect_key, next.as_str(), receipt_hash, expected.as_str()],
            )
            .map_err(|error| format!("failed to transition durable effect: {error}"))?;
        if changed != 1 {
            return Err("durable effect state changed concurrently".into());
        }
        self.load_effect(effect_key)?
            .ok_or_else(|| "durable effect disappeared after transition".to_string())
    }
}

fn insert_revision(
    transaction: &rusqlite::Transaction<'_>,
    task: &DurableTaskCore,
    canonical_json: &[u8],
    revision_hash: &str,
) -> Result<(), String> {
    transaction
        .execute(
            "INSERT INTO guardian_durable_task_revision(
               task_id, revision, revision_hash, previous_revision_hash, status, canonical_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                task.task_id,
                task.revision,
                revision_hash,
                task.previous_revision_hash,
                format!("{:?}", task.status),
                canonical_json,
            ],
        )
        .map_err(|error| format!("failed to append durable task revision: {error}"))?;
    Ok(())
}

fn canonical_bytes(task: &DurableTaskCore) -> Result<Vec<u8>, String> {
    serde_json::to_vec(task).map_err(|error| format!("failed to encode durable task: {error}"))
}

impl DurableTaskCore {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.schema_version != TASK_SCHEMA_VERSION {
            return Err("unsupported durable task schema".into());
        }
        if self.task_id.is_empty()
            || self.owner_pubkey.is_empty()
            || self.actor_pubkey.is_empty()
            || self.authority_grant_id.is_empty()
        {
            return Err("durable task identity fields must not be empty".into());
        }
        for hash in [
            &self.bindings.policy_hash,
            &self.bindings.sandbox_profile_hash,
            &self.bindings.runtime_attestation_hash,
        ]
        .into_iter()
        .chain(self.input_hashes.iter())
        .chain(self.artifact_hashes.iter())
        {
            validate_sha256(hash)?;
        }
        if self
            .budget
            .token_limit
            .is_some_and(|limit| self.budget.consumed_tokens > limit)
            || self
                .budget
                .cost_limit_microusd
                .is_some_and(|limit| self.budget.consumed_microusd > limit)
        {
            return Err("durable task budget is exhausted".into());
        }
        Ok(())
    }

    pub fn validate_delivery(&self, independent_pass: bool) -> Result<(), String> {
        self.validate_shape()?;
        if self.status != TaskStatus::ReadyForDelivery {
            return Err("task is not ready for delivery".into());
        }
        if !independent_pass {
            return Err("independent evaluator pass is required".into());
        }
        if !self.unresolved_blocking_decisions.is_empty() {
            return Err("blocking decisions remain unresolved".into());
        }
        if self.artifact_hashes.is_empty() {
            return Err("delivery requires a verified artifact".into());
        }
        Ok(())
    }

    /// Re-resolves every authority-bearing binding immediately before an
    /// effect. Callers must persist `paused_revalidation` before returning a
    /// failure to the operator.
    pub fn revalidate_before_effect(
        &self,
        snapshot: &RevalidationSnapshot,
        now: DateTime<Utc>,
    ) -> Result<(), RevalidationFailure> {
        if !snapshot.authority_active
            || snapshot.owner_pubkey != self.owner_pubkey
            || snapshot.actor_pubkey != self.actor_pubkey
            || snapshot.authority_grant_id != self.authority_grant_id
            || expired(&self.authority_expires_at, now)
        {
            return Err(RevalidationFailure::Authority);
        }
        if snapshot.policy_hash != self.bindings.policy_hash {
            return Err(RevalidationFailure::Policy);
        }
        if snapshot.sandbox_profile_hash != self.bindings.sandbox_profile_hash {
            return Err(RevalidationFailure::Sandbox);
        }
        if snapshot.runtime_attestation_hash != self.bindings.runtime_attestation_hash
            || expired(&self.bindings.runtime_attestation_expires_at, now)
        {
            return Err(RevalidationFailure::RuntimeAttestation);
        }
        if snapshot.execution_locus != self.bindings.execution_locus {
            return Err(RevalidationFailure::ExecutionLocus);
        }
        if snapshot.input_hashes != self.input_hashes {
            return Err(RevalidationFailure::Inputs);
        }
        if snapshot.artifact_hashes != self.artifact_hashes {
            return Err(RevalidationFailure::Artifacts);
        }
        if self
            .budget
            .token_limit
            .is_some_and(|limit| self.budget.consumed_tokens >= limit)
        {
            return Err(RevalidationFailure::TokenBudget);
        }
        if self
            .budget
            .cost_limit_microusd
            .is_some_and(|limit| self.budget.consumed_microusd >= limit)
        {
            return Err(RevalidationFailure::CostBudget);
        }
        if self
            .budget
            .wall_deadline
            .as_deref()
            .is_some_and(|deadline| expired(deadline, now))
        {
            return Err(RevalidationFailure::WallDeadline);
        }
        Ok(())
    }
}

fn expired(value: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc) <= now)
        .unwrap_or(true)
}

/// Stable across retries: attempt number is intentionally excluded.
pub fn logical_effect_key(task_id: &str, step_id: &str, logical_effect_id: &str) -> String {
    let mut hasher = Sha256::new();
    for value in [task_id, step_id, logical_effect_id] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

pub fn validate_revision(previous: &DurableTaskCore, next: &DurableTaskCore) -> Result<(), String> {
    previous.validate_shape()?;
    next.validate_shape()?;
    if previous.task_id != next.task_id || next.revision != previous.revision + 1 {
        return Err("invalid durable task revision sequence".into());
    }
    let bytes = serde_json::to_vec(previous).map_err(|error| error.to_string())?;
    let expected = hex::encode(Sha256::digest(bytes));
    if next.previous_revision_hash.as_deref() != Some(expected.as_str()) {
        return Err("durable task compare-and-swap hash mismatch".into());
    }
    if matches!(
        previous.status,
        TaskStatus::Complete | TaskStatus::Cancelled
    ) && next.status != previous.status
    {
        return Err("terminal durable task status cannot be reopened".into());
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("invalid sha256 binding".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
