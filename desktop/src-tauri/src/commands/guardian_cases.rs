use std::path::PathBuf;

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager as _};

use crate::{app_state::AppState, managed_agents::managed_agents_base_dir};

use super::numbat_findings::NumbatFindingProjection;

const CASE_SCHEMA_VERSION: &str = "guardian.case/v1";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardianCaseProjection {
    case_id: String,
    title: String,
    status: String,
    severity: String,
    finding_ids: Vec<String>,
    opened_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardianSuppressionProjection {
    suppression_id: String,
    finding_id: String,
    reason: String,
    starts_at: String,
    expires_at: String,
    status: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateGuardianCaseInput {
    agent_pubkey: String,
    finding_ids: Vec<String>,
    title: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateGuardianCaseStatusInput {
    case_id: String,
    status: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateGuardianSuppressionInput {
    agent_pubkey: String,
    finding_id: String,
    reason: String,
    expires_at: String,
}

fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(managed_agents_base_dir(app)?.join("guardian-cases.sqlite3"))
}

fn open_store(app: &AppHandle) -> Result<Connection, String> {
    let path = store_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create Guardian case storage: {error}"))?;
    }
    let connection = Connection::open(path)
        .map_err(|error| format!("failed to open Guardian case storage: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(store_path(app)?)
            .map_err(|error| format!("failed to inspect Guardian case storage: {error}"))?
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(store_path(app)?, permissions)
            .map_err(|error| format!("failed to protect Guardian case storage: {error}"))?;
    }
    initialize(&connection)?;
    Ok(connection)
}

fn initialize(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS guardian_finding (
               finding_id TEXT PRIMARY KEY,
               agent_pubkey TEXT NOT NULL,
               rule_id TEXT NOT NULL,
               title TEXT NOT NULL,
               severity TEXT NOT NULL,
               detected_at TEXT NOT NULL,
               session_id TEXT,
               channel_id TEXT,
               turn_id TEXT,
               evidence_count INTEGER NOT NULL,
               projection_hash TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS guardian_case (
               case_id TEXT PRIMARY KEY,
               schema_version TEXT NOT NULL,
               version INTEGER NOT NULL,
               title TEXT NOT NULL,
               status TEXT NOT NULL,
               severity TEXT NOT NULL,
               agent_pubkey TEXT NOT NULL,
               owner_pubkey TEXT NOT NULL,
               finding_ids_json TEXT NOT NULL,
               previous_version_hash TEXT,
               opened_at TEXT NOT NULL,
               updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS guardian_action (
               action_id TEXT PRIMARY KEY,
               finding_id TEXT,
               case_id TEXT,
               action_type TEXT NOT NULL,
               actor_pubkey TEXT NOT NULL,
               reason TEXT NOT NULL,
               created_at TEXT NOT NULL,
               previous_action_hash TEXT,
               action_hash TEXT NOT NULL UNIQUE
             );
             CREATE TABLE IF NOT EXISTS guardian_suppression (
               suppression_id TEXT PRIMARY KEY,
               schema_version TEXT NOT NULL,
               version INTEGER NOT NULL,
               agent_pubkey TEXT NOT NULL,
               finding_id TEXT NOT NULL,
               reason TEXT NOT NULL,
               created_by TEXT NOT NULL,
               starts_at TEXT NOT NULL,
               expires_at TEXT NOT NULL,
               status TEXT NOT NULL,
               previous_version_hash TEXT
             );",
        )
        .map_err(|error| format!("failed to initialize Guardian case storage: {error}"))
}

pub(crate) fn persist_finding_projections(
    app: &AppHandle,
    findings: &[NumbatFindingProjection],
) -> Result<(), String> {
    if findings.is_empty() {
        return Ok(());
    }
    let mut connection = open_store(app)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("failed to begin Guardian finding transaction: {error}"))?;
    for finding in findings {
        let canonical = serde_json::to_vec(&serde_json::json!({
            "findingId": finding.finding_id,
            "agentPubkey": finding.source_agent,
            "ruleId": finding.rule_id,
            "severity": finding.severity,
            "detectedAt": finding.detected_at,
            "sessionId": finding.session_id,
            "channelId": finding.channel_id,
            "turnId": finding.turn_id,
            "evidenceCount": finding.evidence_count,
        }))
        .map_err(|error| format!("failed to encode Guardian finding: {error}"))?;
        let projection_hash = hex::encode(Sha256::digest(canonical));
        let changed = transaction
            .execute(
                "INSERT INTO guardian_finding(
                   finding_id, agent_pubkey, rule_id, title, severity, detected_at,
                   session_id, channel_id, turn_id, evidence_count, projection_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(finding_id) DO UPDATE SET
                   session_id = excluded.session_id,
                   channel_id = excluded.channel_id,
                   turn_id = excluded.turn_id
                 WHERE guardian_finding.projection_hash = excluded.projection_hash",
                params![
                    finding.finding_id,
                    finding.source_agent,
                    finding.rule_id,
                    finding.title,
                    finding.severity,
                    finding.detected_at,
                    finding.session_id,
                    finding.channel_id,
                    finding.turn_id,
                    finding.evidence_count,
                    projection_hash,
                ],
            )
            .map_err(|error| format!("failed to persist Guardian finding: {error}"))?;
        if changed != 1 {
            return Err("Guardian finding identity conflicts with existing local evidence".into());
        }
    }
    transaction
        .commit()
        .map_err(|error| format!("failed to commit Guardian findings: {error}"))
}

fn owner_pubkey(app: &AppHandle) -> Result<String, String> {
    let state = app.state::<AppState>();
    let keys = state
        .keys
        .lock()
        .map_err(|_| "identity lock poisoned".to_string())?;
    Ok(keys.public_key().to_hex())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn append_action(
    connection: &Connection,
    finding_id: Option<&str>,
    case_id: Option<&str>,
    action_type: &str,
    actor_pubkey: &str,
    reason: &str,
    created_at: &str,
) -> Result<String, String> {
    let previous_hash: Option<String> = connection
        .query_row(
            "SELECT action_hash FROM guardian_action ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("failed to read Guardian audit head: {error}"))?;
    let action_id = uuid::Uuid::new_v4().to_string();
    let canonical = serde_json::to_vec(&serde_json::json!({
        "actionId": action_id,
        "findingId": finding_id,
        "caseId": case_id,
        "actionType": action_type,
        "actorPubkey": actor_pubkey,
        "reason": reason,
        "createdAt": created_at,
        "previousActionHash": previous_hash,
    }))
    .map_err(|error| format!("failed to encode Guardian action: {error}"))?;
    let action_hash = hex::encode(Sha256::digest(canonical));
    connection
        .execute(
            "INSERT INTO guardian_action(
               action_id, finding_id, case_id, action_type, actor_pubkey,
               reason, created_at, previous_action_hash, action_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                action_id,
                finding_id,
                case_id,
                action_type,
                actor_pubkey,
                reason,
                created_at,
                previous_hash,
                action_hash,
            ],
        )
        .map_err(|error| format!("failed to append Guardian action: {error}"))?;
    Ok(action_id)
}

#[tauri::command]
pub fn acknowledge_guardian_finding(
    app: AppHandle,
    agent_pubkey: String,
    finding_id: String,
) -> Result<String, String> {
    validate_identifier(&finding_id, "finding id")?;
    let connection = open_store(&app)?;
    let exists = connection
        .query_row(
            "SELECT 1 FROM guardian_finding WHERE finding_id = ?1 AND agent_pubkey = ?2",
            params![finding_id, agent_pubkey],
            |_| Ok(()),
        )
        .optional()
        .map_err(|error| format!("failed to inspect Guardian finding: {error}"))?
        .is_some();
    if !exists {
        return Err("Guardian finding is not present in local evidence storage".into());
    }
    let actor = owner_pubkey(&app)?;
    if let Some(existing) = connection
        .query_row(
            "SELECT action_id FROM guardian_action
             WHERE finding_id = ?1 AND action_type = 'acknowledge' AND actor_pubkey = ?2
             ORDER BY rowid DESC LIMIT 1",
            params![finding_id, actor],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("failed to inspect Guardian acknowledgement: {error}"))?
    {
        return Ok(existing);
    }
    append_action(
        &connection,
        Some(&finding_id),
        None,
        "acknowledge",
        &actor,
        "Owner acknowledged the local finding",
        &Utc::now().to_rfc3339(),
    )
}

#[tauri::command]
pub fn create_guardian_case(
    app: AppHandle,
    input: CreateGuardianCaseInput,
) -> Result<GuardianCaseProjection, String> {
    let title = input.title.trim();
    if title.is_empty() || title.chars().count() > 120 {
        return Err("case title must contain 1 to 120 characters".into());
    }
    if input.finding_ids.is_empty() || input.finding_ids.len() > 100 {
        return Err("case requires 1 to 100 local findings".into());
    }
    let mut finding_ids = input.finding_ids;
    finding_ids.sort();
    finding_ids.dedup();
    for finding_id in &finding_ids {
        validate_identifier(finding_id, "finding id")?;
    }
    let mut connection = open_store(&app)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("failed to begin Guardian case transaction: {error}"))?;
    let mut severity = "low".to_string();
    for finding_id in &finding_ids {
        let finding_severity: String = transaction
            .query_row(
                "SELECT severity FROM guardian_finding
                 WHERE finding_id = ?1 AND agent_pubkey = ?2",
                params![finding_id, input.agent_pubkey],
                |row| row.get(0),
            )
            .map_err(|_| {
                "case contains a finding outside this agent's local evidence".to_string()
            })?;
        if severity_rank(&finding_severity) > severity_rank(&severity) {
            severity = finding_severity;
        }
    }
    let case_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let actor = owner_pubkey(&app)?;
    let finding_ids_json = serde_json::to_string(&finding_ids)
        .map_err(|error| format!("failed to encode case findings: {error}"))?;
    transaction
        .execute(
            "INSERT INTO guardian_case(
               case_id, schema_version, version, title, status, severity,
               agent_pubkey, owner_pubkey, finding_ids_json, opened_at, updated_at
             ) VALUES (?1, ?2, 1, ?3, 'new', ?4, ?5, ?6, ?7, ?8, ?8)",
            params![
                case_id,
                CASE_SCHEMA_VERSION,
                title,
                severity,
                input.agent_pubkey,
                actor,
                finding_ids_json,
                now,
            ],
        )
        .map_err(|error| format!("failed to create Guardian case: {error}"))?;
    append_action(
        &transaction,
        None,
        Some(&case_id),
        "case_created",
        &actor,
        "Owner grouped local findings into a case",
        &now,
    )?;
    transaction
        .commit()
        .map_err(|error| format!("failed to commit Guardian case: {error}"))?;
    Ok(GuardianCaseProjection {
        case_id,
        title: title.to_string(),
        status: "new".into(),
        severity,
        finding_ids,
        opened_at: now.clone(),
        updated_at: now,
    })
}

#[tauri::command]
pub fn list_guardian_cases(
    app: AppHandle,
    agent_pubkey: String,
) -> Result<Vec<GuardianCaseProjection>, String> {
    let connection = open_store(&app)?;
    let mut statement = connection
        .prepare(
            "SELECT case_id, title, status, severity, finding_ids_json, opened_at, updated_at
             FROM guardian_case WHERE agent_pubkey = ?1 ORDER BY updated_at DESC",
        )
        .map_err(|error| format!("failed to prepare Guardian case query: {error}"))?;
    let rows = statement
        .query_map([agent_pubkey], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| format!("failed to list Guardian cases: {error}"))?;
    rows.map(|row| {
        let (case_id, title, status, severity, findings, opened_at, updated_at) =
            row.map_err(|error| format!("failed to read Guardian case: {error}"))?;
        let finding_ids = serde_json::from_str(&findings)
            .map_err(|error| format!("stored Guardian case is corrupt: {error}"))?;
        Ok(GuardianCaseProjection {
            case_id,
            title,
            status,
            severity,
            finding_ids,
            opened_at,
            updated_at,
        })
    })
    .collect()
}

#[tauri::command]
pub fn update_guardian_case_status(
    app: AppHandle,
    input: UpdateGuardianCaseStatusInput,
) -> Result<GuardianCaseProjection, String> {
    validate_identifier(&input.case_id, "case id")?;
    let mut connection = open_store(&app)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("failed to begin Guardian case update: {error}"))?;
    let row: (String, i64, String, String, String, String, String, String) = transaction
        .query_row(
            "SELECT title, version, status, severity, agent_pubkey,
                    finding_ids_json, opened_at, updated_at
             FROM guardian_case WHERE case_id = ?1",
            [&input.case_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .map_err(|_| "Guardian case does not exist".to_string())?;
    let (title, version, current, severity, _agent, findings, opened_at, updated_at) = row;
    if !valid_case_transition(&current, &input.status) {
        return Err(format!(
            "Guardian case cannot move from {current} to {}",
            input.status
        ));
    }
    let previous = serde_json::to_vec(&serde_json::json!({
        "caseId": input.case_id,
        "version": version,
        "title": title,
        "status": current,
        "severity": severity,
        "findingIds": serde_json::from_str::<serde_json::Value>(&findings).unwrap_or_default(),
        "openedAt": opened_at,
        "updatedAt": updated_at,
    }))
    .map_err(|error| format!("failed to encode Guardian case version: {error}"))?;
    let previous_hash = hex::encode(Sha256::digest(previous));
    let now = Utc::now().to_rfc3339();
    let changed = transaction
        .execute(
            "UPDATE guardian_case SET version = ?1, status = ?2,
                    previous_version_hash = ?3, updated_at = ?4
             WHERE case_id = ?5 AND version = ?6",
            params![
                version + 1,
                input.status,
                previous_hash,
                now,
                input.case_id,
                version,
            ],
        )
        .map_err(|error| format!("failed to update Guardian case: {error}"))?;
    if changed != 1 {
        return Err("Guardian case changed while it was being updated".into());
    }
    let actor = owner_pubkey(&app)?;
    append_action(
        &transaction,
        None,
        Some(&input.case_id),
        "case_status_changed",
        &actor,
        &format!(
            "Owner changed case status from {current} to {}",
            input.status
        ),
        &now,
    )?;
    transaction
        .commit()
        .map_err(|error| format!("failed to commit Guardian case update: {error}"))?;
    Ok(GuardianCaseProjection {
        case_id: input.case_id,
        title,
        status: input.status,
        severity,
        finding_ids: serde_json::from_str(&findings)
            .map_err(|error| format!("stored Guardian case is corrupt: {error}"))?,
        opened_at,
        updated_at: now,
    })
}

#[tauri::command]
pub fn create_guardian_suppression(
    app: AppHandle,
    input: CreateGuardianSuppressionInput,
) -> Result<GuardianSuppressionProjection, String> {
    validate_identifier(&input.finding_id, "finding id")?;
    let reason = input.reason.trim();
    if reason.chars().count() < 3 || reason.chars().count() > 240 {
        return Err("suppression reason must contain 3 to 240 characters".into());
    }
    let now = Utc::now();
    let expiry = chrono::DateTime::parse_from_rfc3339(&input.expires_at)
        .map_err(|_| "suppression expiry must be an RFC3339 timestamp".to_string())?
        .with_timezone(&Utc);
    if expiry <= now || expiry > now + chrono::Duration::days(30) {
        return Err("suppression expiry must be within the next 30 days".into());
    }
    let mut connection = open_store(&app)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("failed to begin Guardian suppression: {error}"))?;
    let finding_exists = transaction
        .query_row(
            "SELECT 1 FROM guardian_finding WHERE finding_id = ?1 AND agent_pubkey = ?2",
            params![input.finding_id, input.agent_pubkey],
            |_| Ok(()),
        )
        .optional()
        .map_err(|error| format!("failed to inspect Guardian finding: {error}"))?
        .is_some();
    if !finding_exists {
        return Err("Guardian finding is not present in local evidence storage".into());
    }
    transaction
        .execute(
            "UPDATE guardian_suppression SET status = 'expired'
             WHERE status = 'active' AND expires_at <= ?1",
            [now.to_rfc3339()],
        )
        .map_err(|error| format!("failed to expire Guardian suppressions: {error}"))?;
    if transaction
        .query_row(
            "SELECT 1 FROM guardian_suppression
             WHERE finding_id = ?1 AND status = 'active' LIMIT 1",
            [&input.finding_id],
            |_| Ok(()),
        )
        .optional()
        .map_err(|error| format!("failed to inspect Guardian suppressions: {error}"))?
        .is_some()
    {
        return Err("this finding already has an active suppression".into());
    }
    let actor = owner_pubkey(&app)?;
    let suppression_id = uuid::Uuid::new_v4().to_string();
    let starts_at = now.to_rfc3339();
    let expires_at = expiry.to_rfc3339();
    transaction
        .execute(
            "INSERT INTO guardian_suppression(
               suppression_id, schema_version, version, agent_pubkey, finding_id,
               reason, created_by, starts_at, expires_at, status
             ) VALUES (?1, 'guardian.suppression/v1', 1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
            params![
                suppression_id,
                input.agent_pubkey,
                input.finding_id,
                reason,
                actor,
                starts_at,
                expires_at,
            ],
        )
        .map_err(|error| format!("failed to create Guardian suppression: {error}"))?;
    append_action(
        &transaction,
        Some(&input.finding_id),
        None,
        "suppression_created",
        &actor,
        reason,
        &starts_at,
    )?;
    transaction
        .commit()
        .map_err(|error| format!("failed to commit Guardian suppression: {error}"))?;
    Ok(GuardianSuppressionProjection {
        suppression_id,
        finding_id: input.finding_id,
        reason: reason.to_string(),
        starts_at,
        expires_at,
        status: "active".into(),
    })
}

#[tauri::command]
pub fn list_guardian_suppressions(
    app: AppHandle,
    agent_pubkey: String,
) -> Result<Vec<GuardianSuppressionProjection>, String> {
    let connection = open_store(&app)?;
    let now = Utc::now().to_rfc3339();
    connection
        .execute(
            "UPDATE guardian_suppression SET status = 'expired'
             WHERE status = 'active' AND expires_at <= ?1",
            [&now],
        )
        .map_err(|error| format!("failed to expire Guardian suppressions: {error}"))?;
    let mut statement = connection
        .prepare(
            "SELECT suppression_id, finding_id, reason, starts_at, expires_at, status
             FROM guardian_suppression WHERE agent_pubkey = ?1 ORDER BY starts_at DESC",
        )
        .map_err(|error| format!("failed to prepare Guardian suppression query: {error}"))?;
    let rows = statement
        .query_map([agent_pubkey], |row| {
            Ok(GuardianSuppressionProjection {
                suppression_id: row.get(0)?,
                finding_id: row.get(1)?,
                reason: row.get(2)?,
                starts_at: row.get(3)?,
                expires_at: row.get(4)?,
                status: row.get(5)?,
            })
        })
        .map_err(|error| format!("failed to list Guardian suppressions: {error}"))?;
    rows.map(|row| row.map_err(|error| format!("failed to read Guardian suppression: {error}")))
        .collect()
}

fn valid_case_transition(current: &str, next: &str) -> bool {
    matches!(
        (current, next),
        ("new", "triaged")
            | ("triaged", "investigating")
            | ("investigating", "resolved")
            | ("resolved", "closed")
            | ("new" | "triaged" | "investigating", "duplicate")
            | ("new" | "triaged" | "investigating", "false_positive")
            | ("new" | "triaged" | "investigating", "accepted_risk")
            | ("closed", "reopened")
            | ("reopened", "investigating")
    )
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_actions_form_a_hash_chain() {
        let connection = Connection::open_in_memory().unwrap();
        initialize(&connection).unwrap();
        let first = append_action(
            &connection,
            Some("finding-1"),
            None,
            "acknowledge",
            "owner",
            "reviewed",
            "2026-08-07T00:00:00Z",
        )
        .unwrap();
        append_action(
            &connection,
            None,
            Some("case-1"),
            "case_created",
            "owner",
            "grouped",
            "2026-08-07T00:01:00Z",
        )
        .unwrap();
        let (previous, count): (Option<String>, i64) = connection
            .query_row(
                "SELECT previous_action_hash, (SELECT COUNT(*) FROM guardian_action)
                 FROM guardian_action WHERE action_id != ?1",
                [first],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(previous.is_some());
        assert_eq!(count, 2);
    }

    #[test]
    fn case_lifecycle_rejects_skips_and_allows_reopen() {
        assert!(valid_case_transition("new", "triaged"));
        assert!(!valid_case_transition("new", "closed"));
        assert!(valid_case_transition("closed", "reopened"));
        assert!(valid_case_transition("investigating", "false_positive"));
    }
}
