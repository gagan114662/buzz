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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectRecord {
    pub effect_key: String,
    pub payload_hash: String,
    pub state: EffectState,
    pub receipt_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskLease {
    pub task_id: String,
    pub holder: String,
    pub generation: u64,
    pub expires_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HandoffRecord {
    pub handoff_id: String,
    pub task_id: String,
    pub task_revision_hash: String,
    pub from_actor: String,
    pub to_actor: String,
    pub next_permitted_step: String,
    pub expires_at: String,
    pub accepted_revision_hash: Option<String>,
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
                 );
                 CREATE TABLE IF NOT EXISTS guardian_durable_task_lease (
                   task_id TEXT PRIMARY KEY,
                   holder TEXT NOT NULL,
                   generation INTEGER NOT NULL,
                   expires_at TEXT NOT NULL,
                   FOREIGN KEY (task_id) REFERENCES guardian_durable_task_head(task_id)
                 );
                 CREATE TABLE IF NOT EXISTS guardian_durable_handoff (
                   handoff_id TEXT PRIMARY KEY,
                   task_id TEXT NOT NULL,
                   task_revision_hash TEXT NOT NULL,
                   from_actor TEXT NOT NULL,
                   to_actor TEXT NOT NULL,
                   next_permitted_step TEXT NOT NULL,
                   expires_at TEXT NOT NULL,
                   accepted_revision_hash TEXT,
                   FOREIGN KEY (task_id) REFERENCES guardian_durable_task_head(task_id)
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

    /// Records an operator- or provider-verified receipt after a crash left an
    /// external effect indeterminate. This is deliberately separate from
    /// `observe_effect`: an uncertain effect must never become retryable or
    /// successful without an explicit reconciliation step.
    pub fn reconcile_indeterminate_effect(
        &mut self,
        effect_key: &str,
        receipt: &[u8],
    ) -> Result<EffectRecord, String> {
        if receipt.is_empty() {
            return Err("durable effect reconciliation requires a receipt".into());
        }
        let receipt_hash = hex::encode(Sha256::digest(receipt));
        self.transition_effect(
            effect_key,
            EffectState::Indeterminate,
            EffectState::Observed,
            Some(&receipt_hash),
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

    /// Acquires a new lease generation only when no live holder exists. Lease
    /// duration is supplied by the authority layer; the store does not invent
    /// a security-sensitive default.
    pub fn acquire_lease(
        &mut self,
        task_id: &str,
        holder: &str,
        expires_at: &str,
        now: DateTime<Utc>,
    ) -> Result<TaskLease, String> {
        if task_id.is_empty() || holder.is_empty() {
            return Err("durable task lease identity must not be empty".into());
        }
        let expiry = DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| "durable task lease expiry must be RFC 3339".to_string())?
            .with_timezone(&Utc);
        if expiry <= now {
            return Err("durable task lease expiry must be in the future".into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("failed to begin durable task lease: {error}"))?;
        let task_exists = transaction
            .query_row(
                "SELECT 1 FROM guardian_durable_task_head WHERE task_id = ?1",
                [task_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| format!("failed to inspect durable task for lease: {error}"))?
            .is_some();
        if !task_exists {
            return Err("durable task does not exist".into());
        }
        let current: Option<(u64, String)> = transaction
            .query_row(
                "SELECT generation, expires_at FROM guardian_durable_task_lease WHERE task_id = ?1",
                [task_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("failed to inspect durable task lease: {error}"))?;
        let generation = match current {
            Some((generation, current_expiry)) => {
                if !expired(&current_expiry, now) {
                    return Err("durable task already has a live lease".into());
                }
                generation
                    .checked_add(1)
                    .ok_or_else(|| "durable task lease generation overflow".to_string())?
            }
            None => 1,
        };
        transaction
            .execute(
                "INSERT INTO guardian_durable_task_lease(task_id, holder, generation, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(task_id) DO UPDATE SET
                   holder = excluded.holder,
                   generation = excluded.generation,
                   expires_at = excluded.expires_at",
                params![task_id, holder, generation, expires_at],
            )
            .map_err(|error| format!("failed to acquire durable task lease: {error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("failed to commit durable task lease: {error}"))?;
        Ok(TaskLease {
            task_id: task_id.to_string(),
            holder: holder.to_string(),
            generation,
            expires_at: expires_at.to_string(),
        })
    }

    /// Extends only the exact live lease generation, preventing a stale worker
    /// from reviving its authority after recovery selected a new holder.
    pub fn renew_lease(
        &mut self,
        lease: &TaskLease,
        expires_at: &str,
        now: DateTime<Utc>,
    ) -> Result<TaskLease, String> {
        let expiry = DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| "durable task lease expiry must be RFC 3339".to_string())?
            .with_timezone(&Utc);
        if expiry <= now {
            return Err("durable task lease expiry must be in the future".into());
        }
        let changed = self
            .connection
            .execute(
                "UPDATE guardian_durable_task_lease SET expires_at = ?4
                 WHERE task_id = ?1 AND holder = ?2 AND generation = ?3 AND expires_at > ?5",
                params![
                    lease.task_id,
                    lease.holder,
                    lease.generation,
                    expires_at,
                    now.to_rfc3339()
                ],
            )
            .map_err(|error| format!("failed to renew durable task lease: {error}"))?;
        if changed != 1 {
            return Err("durable task lease is stale or expired".into());
        }
        Ok(TaskLease {
            expires_at: expires_at.to_string(),
            ..lease.clone()
        })
    }

    pub fn create_handoff(
        &mut self,
        task_id: &str,
        expected_revision_hash: &str,
        to_actor: &str,
        next_permitted_step: &str,
        expires_at: &str,
        now: DateTime<Utc>,
    ) -> Result<HandoffRecord, String> {
        validate_sha256(expected_revision_hash)?;
        if to_actor.is_empty() || next_permitted_step.is_empty() {
            return Err("durable handoff recipient and next step must not be empty".into());
        }
        if expired(expires_at, now) {
            return Err("durable handoff expiry must be in the future".into());
        }
        let (task, head_hash) = self
            .load_head(task_id)?
            .ok_or_else(|| "durable task does not exist".to_string())?;
        if head_hash != expected_revision_hash {
            return Err("durable handoff task revision is stale".into());
        }
        if task.actor_pubkey == to_actor {
            return Err("durable handoff recipient must differ from the current actor".into());
        }
        let handoff_id = uuid::Uuid::new_v4().to_string();
        self.connection
            .execute(
                "INSERT INTO guardian_durable_handoff(
                   handoff_id, task_id, task_revision_hash, from_actor, to_actor,
                   next_permitted_step, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    handoff_id,
                    task_id,
                    expected_revision_hash,
                    task.actor_pubkey,
                    to_actor,
                    next_permitted_step,
                    expires_at
                ],
            )
            .map_err(|error| format!("failed to create durable handoff: {error}"))?;
        Ok(HandoffRecord {
            handoff_id,
            task_id: task_id.to_string(),
            task_revision_hash: expected_revision_hash.to_string(),
            from_actor: task.actor_pubkey,
            to_actor: to_actor.to_string(),
            next_permitted_step: next_permitted_step.to_string(),
            expires_at: expires_at.to_string(),
            accepted_revision_hash: None,
        })
    }

    /// Acceptance and task-head transfer commit atomically. The caller must
    /// supply a new task revision whose authority explicitly names the recipient.
    pub fn accept_handoff(
        &mut self,
        handoff_id: &str,
        recipient: &str,
        next: &DurableTaskCore,
        now: DateTime<Utc>,
    ) -> Result<String, String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("failed to begin durable handoff acceptance: {error}"))?;
        let (task_id, revision_hash, from_actor, to_actor, expires_at, accepted): (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
        ) = transaction
            .query_row(
                "SELECT task_id, task_revision_hash, from_actor, to_actor, expires_at,
                        accepted_revision_hash
                 FROM guardian_durable_handoff WHERE handoff_id = ?1",
                [handoff_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(|_| "durable handoff does not exist".to_string())?;
        if accepted.is_some() {
            return Err("durable handoff was already accepted".into());
        }
        if recipient != to_actor || next.actor_pubkey != to_actor || next.actor_pubkey == from_actor
        {
            return Err("durable handoff recipient lacks an exactly bound task revision".into());
        }
        if expired(&expires_at, now) {
            return Err("durable handoff has expired".into());
        }
        let (head_hash, bytes): (String, Vec<u8>) = transaction
            .query_row(
                "SELECT h.revision_hash, r.canonical_json
                 FROM guardian_durable_task_head h
                 JOIN guardian_durable_task_revision r
                   ON r.task_id = h.task_id AND r.revision = h.revision
                 WHERE h.task_id = ?1",
                [&task_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| format!("durable handoff task head is unavailable: {error}"))?;
        if head_hash != revision_hash || next.task_id != task_id {
            return Err("durable handoff lost its task revision race".into());
        }
        let previous: DurableTaskCore = serde_json::from_slice(&bytes)
            .map_err(|error| format!("stored durable task is corrupt: {error}"))?;
        validate_revision(&previous, next)?;
        if next.authority_grant_id == previous.authority_grant_id {
            return Err("durable handoff requires a new recipient-bound authority grant".into());
        }
        let next_bytes = canonical_bytes(next)?;
        let next_hash = hex::encode(Sha256::digest(&next_bytes));
        insert_revision(&transaction, next, &next_bytes, &next_hash)?;
        let changed = transaction
            .execute(
                "UPDATE guardian_durable_task_head SET revision = ?1, revision_hash = ?2
                 WHERE task_id = ?3 AND revision_hash = ?4",
                params![next.revision, next_hash, task_id, revision_hash],
            )
            .map_err(|error| format!("failed to transfer durable handoff task: {error}"))?;
        if changed != 1 {
            return Err("durable handoff lost its task revision race".into());
        }
        transaction
            .execute(
                "UPDATE guardian_durable_handoff SET accepted_revision_hash = ?2
                 WHERE handoff_id = ?1 AND accepted_revision_hash IS NULL",
                params![handoff_id, next_hash],
            )
            .map_err(|error| format!("failed to record durable handoff acceptance: {error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("failed to commit durable handoff acceptance: {error}"))?;
        Ok(next_hash)
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
#[path = "durable_tasks_tests.rs"]
mod tests;
