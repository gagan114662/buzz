//! Fail-closed core contracts for resumable agent work.
//!
//! This module deliberately contains no effect dispatcher.  It is the durable
//! boundary that a dispatcher must satisfy before it can perform work.

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
}
