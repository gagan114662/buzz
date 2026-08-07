use std::path::PathBuf;

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, State};

use crate::{
    app_state::AppState,
    managed_agents::{
        load_managed_agents, managed_agents_base_dir, restart_managed_agent_runtime,
        save_managed_agents,
    },
};

const SCHEMA_VERSION: &str = "guardian.policy/v1";
const CORPUS_VERSION: &str = "guardian.policy-corpus/v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardianPolicyRule {
    operation: String,
    decision: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateGuardianPolicyDraftInput {
    agent_pubkey: String,
    name: String,
    mode: String,
    rules: Vec<GuardianPolicyRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionGuardianPolicyInput {
    policy_hash: String,
    action: String,
    target_agent_pubkey: Option<String>,
    approval_expires_at: Option<String>,
    rollback_target_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardianPolicyVersion {
    policy_hash: String,
    schema_version: String,
    agent_pubkey: String,
    name: String,
    mode: String,
    rules: Vec<GuardianPolicyRule>,
    state: String,
    corpus_version: Option<String>,
    simulation_hash: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardianPolicySimulation {
    policy_hash: String,
    corpus_version: String,
    simulation_hash: String,
    passed: bool,
    allow_count: usize,
    deny_count: usize,
    unsupported_count: usize,
    partitions: Vec<String>,
}

fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(managed_agents_base_dir(app)?.join("guardian-policies.sqlite3"))
}

fn open_store(app: &AppHandle) -> Result<Connection, String> {
    let path = store_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create Guardian policy storage: {error}"))?;
    }
    let connection = Connection::open(&path)
        .map_err(|error| format!("failed to open Guardian policy storage: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&path)
            .map_err(|error| format!("failed to inspect Guardian policy storage: {error}"))?
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&path, permissions)
            .map_err(|error| format!("failed to protect Guardian policy storage: {error}"))?;
    }
    initialize(&connection)?;
    Ok(connection)
}

fn initialize(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS guardian_policy_version (
           policy_hash TEXT PRIMARY KEY,
           schema_version TEXT NOT NULL,
           agent_pubkey TEXT NOT NULL,
           name TEXT NOT NULL,
           mode TEXT NOT NULL,
           rules_json TEXT NOT NULL,
           state TEXT NOT NULL,
           corpus_version TEXT,
           simulation_hash TEXT,
           created_at TEXT NOT NULL,
           updated_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS guardian_policy_transition (
           transition_id TEXT PRIMARY KEY,
           policy_hash TEXT NOT NULL,
           from_state TEXT NOT NULL,
           to_state TEXT NOT NULL,
           action TEXT NOT NULL,
           created_at TEXT NOT NULL,
           previous_transition_hash TEXT,
           transition_hash TEXT NOT NULL UNIQUE
         );",
        )
        .map_err(|error| format!("failed to initialize Guardian policy storage: {error}"))
}

fn validate_text(value: &str, label: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn validate_agent(value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid agent public key".into());
    }
    Ok(())
}

fn validate_rules(rules: &[GuardianPolicyRule]) -> Result<(), String> {
    if rules.is_empty() || rules.len() > 100 {
        return Err("policy must contain 1 to 100 rules".into());
    }
    for rule in rules {
        validate_text(&rule.operation, "policy operation", 160)?;
        if !matches!(rule.decision.as_str(), "allow" | "deny") {
            return Err("policy rule decision must be allow or deny".into());
        }
    }
    Ok(())
}

fn canonical_policy(input: &CreateGuardianPolicyDraftInput) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": SCHEMA_VERSION,
        "agentPubkey": input.agent_pubkey.to_lowercase(),
        "name": input.name.trim(),
        "mode": input.mode,
        "rules": input.rules,
    }))
    .map_err(|error| format!("failed to encode Guardian policy: {error}"))
}

fn read_policy(
    connection: &Connection,
    policy_hash: &str,
) -> Result<GuardianPolicyVersion, String> {
    connection
        .query_row(
            "SELECT policy_hash, schema_version, agent_pubkey, name, mode, rules_json,
                state, corpus_version, simulation_hash, created_at, updated_at
         FROM guardian_policy_version WHERE policy_hash = ?1",
            [policy_hash],
            |row| {
                let rules_json: String = row.get(5)?;
                let rules = serde_json::from_str(&rules_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok(GuardianPolicyVersion {
                    policy_hash: row.get(0)?,
                    schema_version: row.get(1)?,
                    agent_pubkey: row.get(2)?,
                    name: row.get(3)?,
                    mode: row.get(4)?,
                    rules,
                    state: row.get(6)?,
                    corpus_version: row.get(7)?,
                    simulation_hash: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(|error| format!("failed to read Guardian policy: {error}"))?
        .ok_or_else(|| "Guardian policy version was not found".into())
}

#[tauri::command]
pub fn create_guardian_policy_draft(
    app: AppHandle,
    input: CreateGuardianPolicyDraftInput,
) -> Result<GuardianPolicyVersion, String> {
    validate_agent(&input.agent_pubkey)?;
    validate_text(&input.name, "policy name", 120)?;
    if !matches!(input.mode.as_str(), "monitor" | "deny") {
        return Err("policy mode must be monitor or deny".into());
    }
    validate_rules(&input.rules)?;
    let canonical = canonical_policy(&input)?;
    let policy_hash = hex::encode(Sha256::digest(&canonical));
    let rules_json = serde_json::to_string(&input.rules)
        .map_err(|error| format!("failed to encode Guardian policy rules: {error}"))?;
    let now = Utc::now().to_rfc3339();
    let connection = open_store(&app)?;
    connection
        .execute(
            "INSERT OR IGNORE INTO guardian_policy_version(
           policy_hash, schema_version, agent_pubkey, name, mode, rules_json,
           state, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'draft', ?7, ?7)",
            params![
                policy_hash,
                SCHEMA_VERSION,
                input.agent_pubkey.to_lowercase(),
                input.name.trim(),
                input.mode,
                rules_json,
                now
            ],
        )
        .map_err(|error| format!("failed to persist Guardian policy draft: {error}"))?;
    read_policy(&connection, &policy_hash)
}

#[tauri::command]
pub fn list_guardian_policy_versions(
    app: AppHandle,
    agent_pubkey: String,
) -> Result<Vec<GuardianPolicyVersion>, String> {
    validate_agent(&agent_pubkey)?;
    let connection = open_store(&app)?;
    let mut statement = connection.prepare(
        "SELECT policy_hash FROM guardian_policy_version WHERE agent_pubkey = ?1 ORDER BY rowid DESC"
    ).map_err(|error| format!("failed to prepare Guardian policy list: {error}"))?;
    let hashes = statement
        .query_map([agent_pubkey.to_lowercase()], |row| row.get::<_, String>(0))
        .map_err(|error| format!("failed to list Guardian policies: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to decode Guardian policy list: {error}"))?;
    hashes
        .iter()
        .map(|hash| read_policy(&connection, hash))
        .collect()
}

fn simulate(policy: &GuardianPolicyVersion) -> Result<GuardianPolicySimulation, String> {
    let partitions = vec![
        "allow",
        "deny",
        "boundary",
        "runtime-adapters",
        "regressions",
        "resource",
        "privacy",
    ];
    let operations = [
        "read",
        "write",
        "network",
        "shell",
        "browser",
        "secrets",
        "unknown-adapter",
    ];
    let mut allow_count = 0;
    let mut deny_count = 0;
    let mut unsupported_count = 0;
    for operation in operations {
        match policy
            .rules
            .iter()
            .find(|rule| rule.operation == operation)
            .map(|rule| rule.decision.as_str())
        {
            Some("allow") => allow_count += 1,
            Some("deny") => deny_count += 1,
            _ => unsupported_count += 1,
        }
    }
    let passed = policy.mode == "monitor" || unsupported_count == 0;
    let canonical = serde_json::to_vec(&serde_json::json!({
        "policyHash": policy.policy_hash, "corpusVersion": CORPUS_VERSION,
        "allowCount": allow_count, "denyCount": deny_count,
        "unsupportedCount": unsupported_count, "partitions": partitions,
    }))
    .map_err(|error| format!("failed to encode Guardian simulation: {error}"))?;
    Ok(GuardianPolicySimulation {
        policy_hash: policy.policy_hash.clone(),
        corpus_version: CORPUS_VERSION.into(),
        simulation_hash: hex::encode(Sha256::digest(canonical)),
        passed,
        allow_count,
        deny_count,
        unsupported_count,
        partitions: partitions.into_iter().map(str::to_string).collect(),
    })
}

#[tauri::command]
pub fn simulate_guardian_policy(
    app: AppHandle,
    policy_hash: String,
) -> Result<GuardianPolicySimulation, String> {
    let mut connection = open_store(&app)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("failed to begin Guardian policy simulation: {error}"))?;
    let policy = read_policy(&transaction, &policy_hash)?;
    if policy.state != "draft" && policy.state != "simulated" {
        return Err("only draft policies can be simulated".into());
    }
    let result = simulate(&policy)?;
    let now = Utc::now().to_rfc3339();
    transaction.execute(
        "UPDATE guardian_policy_version SET state = 'simulated', corpus_version = ?2,
         simulation_hash = ?3, updated_at = ?4 WHERE policy_hash = ?1 AND state IN ('draft', 'simulated')",
        params![policy_hash, result.corpus_version, result.simulation_hash, now],
    ).map_err(|error| format!("failed to persist Guardian policy simulation: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("failed to commit Guardian policy simulation: {error}"))?;
    Ok(result)
}

fn next_state(state: &str, action: &str, simulation_passed: bool) -> Result<&'static str, String> {
    match (state, action) {
        ("simulated", "request_approval") if simulation_passed => Ok("awaiting_approval"),
        ("awaiting_approval", "approve") => Ok("approved"),
        ("approved", "stage_local_canary") => Ok("staged"),
        ("staged", "activate") => Ok("active"),
        ("active", "pause") => Ok("paused"),
        ("paused", "activate") => Ok("active"),
        ("active" | "paused" | "staged", "rollback") => Ok("rolled_back"),
        ("draft" | "simulated" | "awaiting_approval" | "approved", "abandon") => Ok("abandoned"),
        (_, "stage_team_canary" | "stage_percentage" | "stage_all") => {
            Err("fleet rollout requires an organization trust decision".into())
        }
        ("simulated", "request_approval") => {
            Err("deny policy simulation is incomplete or indeterminate".into())
        }
        _ => Err(format!(
            "illegal Guardian policy transition: {state} -> {action}"
        )),
    }
}

#[tauri::command]
pub fn transition_guardian_policy(
    app: AppHandle,
    state: State<'_, AppState>,
    input: TransitionGuardianPolicyInput,
) -> Result<GuardianPolicyVersion, String> {
    let mut connection = open_store(&app)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("failed to begin Guardian policy transition: {error}"))?;
    let policy = read_policy(&transaction, &input.policy_hash)?;
    let rollback_target = if input.action == "rollback" {
        let target_hash = input
            .rollback_target_hash
            .as_deref()
            .ok_or_else(|| "rollback must name an exact verified policy version".to_string())?;
        let target = read_policy(&transaction, target_hash)?;
        if target.policy_hash == policy.policy_hash
            || target.agent_pubkey != policy.agent_pubkey
            || target.simulation_hash.is_none()
            || !matches!(
                target.state.as_str(),
                "approved" | "paused" | "rolled_back" | "active"
            )
        {
            return Err(
                "rollback target is not a different verified version for this agent".into(),
            );
        }
        Some(target)
    } else {
        None
    };
    if input.action == "approve" {
        let target = input
            .target_agent_pubkey
            .as_deref()
            .ok_or_else(|| "approval must bind an exact target agent".to_string())?;
        validate_agent(target)?;
        if !target.eq_ignore_ascii_case(&policy.agent_pubkey) {
            return Err("approval target does not match the immutable policy target".into());
        }
        let expires_at = input
            .approval_expires_at
            .as_deref()
            .ok_or_else(|| "approval must include an expiry".to_string())?;
        let expiry = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| "approval expiry must be RFC 3339".to_string())?;
        if expiry <= Utc::now() || expiry > Utc::now() + chrono::Duration::days(30) {
            return Err(
                "approval expiry must be in the future and no more than 30 days away".into(),
            );
        }
    }
    let simulation_passed = if policy.state == "simulated" {
        simulate(&policy)?.passed
    } else {
        true
    };
    let to_state = next_state(&policy.state, &input.action, simulation_passed)?;
    if to_state == "active" {
        apply_runtime_policy(&app, &state, &policy)?;
    } else if to_state == "rolled_back" {
        apply_runtime_policy(
            &app,
            &state,
            rollback_target.as_ref().expect("rollback target validated"),
        )?;
    }
    let now = Utc::now().to_rfc3339();
    let previous_hash: Option<String> = transaction
        .query_row(
            "SELECT transition_hash FROM guardian_policy_transition ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("failed to read Guardian policy audit head: {error}"))?;
    let transition_id = uuid::Uuid::new_v4().to_string();
    let canonical = serde_json::to_vec(&serde_json::json!({
        "transitionId": transition_id, "policyHash": input.policy_hash,
        "fromState": policy.state, "toState": to_state, "action": input.action,
        "targetAgentPubkey": input.target_agent_pubkey,
        "approvalExpiresAt": input.approval_expires_at,
        "rollbackTargetHash": input.rollback_target_hash,
        "createdAt": now, "previousTransitionHash": previous_hash,
    }))
    .map_err(|error| format!("failed to encode Guardian policy transition: {error}"))?;
    let transition_hash = hex::encode(Sha256::digest(canonical));
    let changed = transaction.execute(
        "UPDATE guardian_policy_version SET state = ?2, updated_at = ?3 WHERE policy_hash = ?1 AND state = ?4",
        params![input.policy_hash, to_state, now, policy.state],
    ).map_err(|error| format!("failed to update Guardian policy state: {error}"))?;
    if changed != 1 {
        return Err("Guardian policy changed concurrently".into());
    }
    transaction
        .execute(
            "INSERT INTO guardian_policy_transition VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                transition_id,
                input.policy_hash,
                policy.state,
                to_state,
                input.action,
                now,
                previous_hash,
                transition_hash
            ],
        )
        .map_err(|error| format!("failed to append Guardian policy transition: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("failed to commit Guardian policy transition: {error}"))?;
    let connection = open_store(&app)?;
    read_policy(&connection, &input.policy_hash)
}

fn apply_runtime_policy(
    app: &AppHandle,
    state: &AppState,
    policy: &GuardianPolicyVersion,
) -> Result<(), String> {
    let env_value = match policy.mode.as_str() {
        "monitor" => "default",
        "deny" => "dont-ask",
        _ => return Err("Guardian policy has an unsupported runtime mode".into()),
    };
    let (previous_env, relay_url) = {
        let _guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|_| "managed-agent storage lock poisoned".to_string())?;
        let mut records = load_managed_agents(app)?;
        let record = records
            .iter_mut()
            .find(|record| record.pubkey.eq_ignore_ascii_case(&policy.agent_pubkey))
            .ok_or_else(|| "policy target is not a locally managed agent".to_string())?;
        let previous_env = record.env_vars.clone();
        record
            .env_vars
            .insert("BUZZ_ACP_PERMISSION_MODE".into(), env_value.to_string());
        let relay_url = crate::relay::effective_agent_relay_url(
            &record.relay_url,
            &crate::relay::relay_ws_url_with_override(state),
        );
        save_managed_agents(app, &records)?;
        (previous_env, relay_url)
    };
    if let Err(error) =
        restart_managed_agent_runtime(policy.agent_pubkey.clone(), relay_url.clone(), app.clone())
    {
        let restore_result = (|| {
            let _guard = state
                .managed_agents_store_lock
                .lock()
                .map_err(|_| "managed-agent storage lock poisoned".to_string())?;
            let mut records = load_managed_agents(app)?;
            let record = records
                .iter_mut()
                .find(|record| record.pubkey.eq_ignore_ascii_case(&policy.agent_pubkey))
                .ok_or_else(|| "policy target disappeared during rollback".to_string())?;
            record.env_vars = previous_env;
            save_managed_agents(app, &records)
        })();
        let _ = restart_managed_agent_runtime(policy.agent_pubkey.clone(), relay_url, app.clone());
        return match restore_result {
            Ok(()) => Err(format!(
                "policy activation failed and prior runtime configuration was restored: {error}"
            )),
            Err(restore_error) => Err(format!(
                "policy activation failed ({error}); restoring prior configuration also failed ({restore_error})"
            )),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mode: &str, rules: &[(&str, &str)]) -> GuardianPolicyVersion {
        GuardianPolicyVersion {
            policy_hash: "a".repeat(64),
            schema_version: SCHEMA_VERSION.into(),
            agent_pubkey: "b".repeat(64),
            name: "test".into(),
            mode: mode.into(),
            rules: rules
                .iter()
                .map(|(operation, decision)| GuardianPolicyRule {
                    operation: (*operation).into(),
                    decision: (*decision).into(),
                })
                .collect(),
            state: "draft".into(),
            corpus_version: None,
            simulation_hash: None,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn deny_simulation_fails_closed_for_unknown_adapter() {
        let result = simulate(&policy("deny", &[("read", "allow")])).unwrap();
        assert!(!result.passed);
        assert!(result.unsupported_count > 0);
    }

    #[test]
    fn complete_deny_simulation_can_advance() {
        let operations = [
            "read",
            "write",
            "network",
            "shell",
            "browser",
            "secrets",
            "unknown-adapter",
        ];
        let rules: Vec<_> = operations
            .iter()
            .map(|operation| (*operation, "deny"))
            .collect();
        let result = simulate(&policy("deny", &rules)).unwrap();
        assert!(result.passed);
        assert_eq!(
            next_state("simulated", "request_approval", result.passed).unwrap(),
            "awaiting_approval"
        );
    }

    #[test]
    fn reducer_rejects_skips_and_unapproved_fleet_rollouts() {
        assert!(next_state("draft", "activate", true).is_err());
        assert!(next_state("approved", "stage_all", true)
            .unwrap_err()
            .contains("trust decision"));
    }
}
