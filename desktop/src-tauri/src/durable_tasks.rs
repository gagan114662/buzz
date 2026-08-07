//! Fail-closed core contracts for resumable agent work.
//!
//! This module deliberately contains no effect dispatcher.  It is the durable
//! boundary that a dispatcher must satisfy before it can perform work.

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
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
}
