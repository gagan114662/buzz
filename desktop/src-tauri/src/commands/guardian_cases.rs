use std::{
    io::{Cursor, Read as _, Write as _},
    path::PathBuf,
};

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager as _};

use crate::{app_state::AppState, managed_agents::managed_agents_base_dir};

use super::numbat_findings::NumbatFindingProjection;

const CASE_SCHEMA_VERSION: &str = "guardian.case/v1";
const EXPORT_SCHEMA_VERSION: &str = "guardian.case-export/v1";

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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelGuardianSuppressionInput {
    suppression_id: String,
    reason: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportGuardianCaseInput {
    case_id: String,
    profile: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportGuardianCaseInput {
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardianCaseImportPreview {
    schema_version: String,
    profile: String,
    case_id: String,
    file_count: usize,
    verified: bool,
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
             );
             CREATE TABLE IF NOT EXISTS guardian_export (
               export_id TEXT PRIMARY KEY,
               case_id TEXT NOT NULL,
               profile TEXT NOT NULL,
               manifest_hash TEXT NOT NULL,
               destination_kind TEXT NOT NULL,
               created_by TEXT NOT NULL,
               created_at TEXT NOT NULL,
               result TEXT NOT NULL
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

fn read_case_projection(
    connection: &Connection,
    case_id: &str,
) -> Result<GuardianCaseProjection, String> {
    let row: (String, String, String, String, String, String, String) = connection
        .query_row(
            "SELECT case_id, title, status, severity, finding_ids_json, opened_at, updated_at
             FROM guardian_case WHERE case_id = ?1",
            [case_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .map_err(|_| "Guardian case does not exist".to_string())?;
    Ok(GuardianCaseProjection {
        case_id: row.0,
        title: row.1,
        status: row.2,
        severity: row.3,
        finding_ids: serde_json::from_str(&row.4)
            .map_err(|error| format!("stored Guardian case is corrupt: {error}"))?,
        opened_at: row.5,
        updated_at: row.6,
    })
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

#[tauri::command]
pub fn cancel_guardian_suppression(
    app: AppHandle,
    input: CancelGuardianSuppressionInput,
) -> Result<GuardianSuppressionProjection, String> {
    validate_identifier(&input.suppression_id, "suppression id")?;
    let reason = input.reason.trim();
    if reason.chars().count() < 3 || reason.chars().count() > 240 {
        return Err("cancellation reason must contain 3 to 240 characters".into());
    }
    let mut connection = open_store(&app)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("failed to begin Guardian suppression cancellation: {error}"))?;
    let row: (String, i64, String, String, String, String) = transaction
        .query_row(
            "SELECT finding_id, version, reason, starts_at, expires_at, status
             FROM guardian_suppression WHERE suppression_id = ?1",
            [&input.suppression_id],
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
        .map_err(|_| "Guardian suppression does not exist".to_string())?;
    let (finding_id, version, prior_reason, starts_at, expires_at, status) = row;
    if status != "active" {
        return Err("only an active Guardian suppression can be cancelled".into());
    }
    let previous = serde_json::to_vec(&serde_json::json!({
        "suppressionId": input.suppression_id,
        "version": version,
        "findingId": finding_id,
        "reason": prior_reason,
        "startsAt": starts_at,
        "expiresAt": expires_at,
        "status": status,
    }))
    .map_err(|error| format!("failed to encode Guardian suppression version: {error}"))?;
    let previous_hash = hex::encode(Sha256::digest(previous));
    let changed = transaction
        .execute(
            "UPDATE guardian_suppression SET version = ?2, status = 'cancelled',
                    previous_version_hash = ?3
             WHERE suppression_id = ?1 AND version = ?4 AND status = 'active'",
            params![input.suppression_id, version + 1, previous_hash, version],
        )
        .map_err(|error| format!("failed to cancel Guardian suppression: {error}"))?;
    if changed != 1 {
        return Err("Guardian suppression changed while it was being cancelled".into());
    }
    let actor = owner_pubkey(&app)?;
    let now = Utc::now().to_rfc3339();
    append_action(
        &transaction,
        Some(&finding_id),
        None,
        "suppression_cancelled",
        &actor,
        reason,
        &now,
    )?;
    transaction
        .commit()
        .map_err(|error| format!("failed to commit Guardian suppression cancellation: {error}"))?;
    Ok(GuardianSuppressionProjection {
        suppression_id: input.suppression_id,
        finding_id,
        reason: prior_reason,
        starts_at,
        expires_at,
        status: "cancelled".into(),
    })
}

fn zip_bundle(files: &[(String, Vec<u8>)], manifest: &[u8]) -> Result<Vec<u8>, String> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o600);
    writer
        .start_file("manifest.json", options)
        .map_err(|error| format!("failed to start Guardian bundle manifest: {error}"))?;
    writer
        .write_all(manifest)
        .map_err(|error| format!("failed to write Guardian bundle manifest: {error}"))?;
    for (name, contents) in files {
        writer
            .start_file(name, options)
            .map_err(|error| format!("failed to start Guardian bundle entry: {error}"))?;
        writer
            .write_all(contents)
            .map_err(|error| format!("failed to write Guardian bundle entry: {error}"))?;
    }
    writer
        .finish()
        .map(|cursor| cursor.into_inner())
        .map_err(|error| format!("failed to finish Guardian bundle: {error}"))
}

#[tauri::command]
pub fn export_guardian_case_bundle(
    app: AppHandle,
    input: ExportGuardianCaseInput,
) -> Result<Vec<u8>, String> {
    validate_identifier(&input.case_id, "case id")?;
    if !matches!(input.profile.as_str(), "redacted" | "regression") {
        return Err("full forensic export requires a fresh destination-specific owner confirmation and is not available from this command".into());
    }
    let connection = open_store(&app)?;
    let case = read_case_projection(&connection, &input.case_id)?;
    let agent_pubkey: String = connection
        .query_row(
            "SELECT agent_pubkey FROM guardian_case WHERE case_id = ?1",
            [&input.case_id],
            |row| row.get(0),
        )
        .map_err(|error| format!("failed to read Guardian case owner: {error}"))?;
    let mut findings = Vec::new();
    for finding_id in &case.finding_ids {
        let finding = connection
            .query_row(
                "SELECT finding_id, rule_id, severity, detected_at, evidence_count, projection_hash
                 FROM guardian_finding WHERE finding_id = ?1",
                [finding_id],
                |row| {
                    Ok(serde_json::json!({
                        "findingId": row.get::<_, String>(0)?,
                        "ruleId": row.get::<_, String>(1)?,
                        "severity": row.get::<_, String>(2)?,
                        "detectedAt": row.get::<_, String>(3)?,
                        "evidenceCount": row.get::<_, i64>(4)?,
                        "projectionHash": row.get::<_, String>(5)?,
                    }))
                },
            )
            .map_err(|error| format!("failed to read Guardian export finding: {error}"))?;
        findings.push(finding);
    }
    let payload = if input.profile == "redacted" {
        serde_json::json!({ "case": case, "findings": findings })
    } else {
        serde_json::json!({
            "fixtureSchemaVersion": "guardian.regression-fixture/v1",
            "expectedFindings": findings.iter().map(|finding| serde_json::json!({
                "ruleId": finding["ruleId"], "severity": finding["severity"]
            })).collect::<Vec<_>>()
        })
    };
    let entry_name = if input.profile == "redacted" {
        "case.json"
    } else {
        "fixture.json"
    };
    let payload_bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|error| format!("failed to encode Guardian export payload: {error}"))?;
    let files = vec![(entry_name.to_string(), payload_bytes)];
    let file_manifest = files
        .iter()
        .map(|(name, bytes)| {
            serde_json::json!({
                "name": name, "sha256": hex::encode(Sha256::digest(bytes)), "size": bytes.len()
            })
        })
        .collect::<Vec<_>>();
    let endpoint_pseudonym = hex::encode(Sha256::digest(format!("guardian-export:{agent_pubkey}")));
    let manifest_value = serde_json::json!({
        "schemaVersion": EXPORT_SCHEMA_VERSION,
        "exporterVersion": env!("CARGO_PKG_VERSION"),
        "profile": input.profile,
        "caseId": input.case_id,
        "sourceEndpointPseudonym": endpoint_pseudonym,
        "createdAt": Utc::now().to_rfc3339(),
        "files": file_manifest,
    });
    let manifest = serde_json::to_vec_pretty(&manifest_value)
        .map_err(|error| format!("failed to encode Guardian export manifest: {error}"))?;
    let manifest_hash = hex::encode(Sha256::digest(&manifest));
    let bundle = zip_bundle(&files, &manifest)?;
    let actor = owner_pubkey(&app)?;
    let export_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    connection
        .execute(
            "INSERT INTO guardian_export VALUES (?1, ?2, ?3, ?4, 'download', ?5, ?6, 'completed')",
            params![
                export_id,
                input.case_id,
                input.profile,
                manifest_hash,
                actor,
                now
            ],
        )
        .map_err(|error| format!("failed to record Guardian export: {error}"))?;
    append_action(
        &connection,
        None,
        Some(&input.case_id),
        "case_exported",
        &actor,
        "Owner exported a verified local case bundle",
        &now,
    )?;
    Ok(bundle)
}

#[tauri::command]
pub async fn save_guardian_case_bundle(
    app: AppHandle,
    input: ExportGuardianCaseInput,
) -> Result<bool, String> {
    let bytes = export_guardian_case_bundle(app.clone(), input.clone())?;
    let filename = format!("guardian-case-{}-{}.zip", input.case_id, input.profile);
    super::export_util::save_bytes_with_dialog(
        &app,
        &filename,
        "Guardian case bundle",
        &["zip"],
        &bytes,
    )
    .await
}

#[tauri::command]
pub fn import_guardian_case_bundle(
    input: ImportGuardianCaseInput,
) -> Result<GuardianCaseImportPreview, String> {
    if input.bytes.is_empty() || input.bytes.len() > 16 * 1024 * 1024 {
        return Err("Guardian bundle must be between 1 byte and 16 MiB".into());
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(input.bytes))
        .map_err(|error| format!("invalid Guardian bundle: {error}"))?;
    if archive.len() < 2 || archive.len() > 16 {
        return Err("Guardian bundle has an invalid file count".into());
    }
    let mut manifest_bytes = Vec::new();
    archive
        .by_name("manifest.json")
        .map_err(|_| "Guardian bundle has no manifest.json".to_string())?
        .read_to_end(&mut manifest_bytes)
        .map_err(|error| format!("failed to read Guardian bundle manifest: {error}"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid Guardian bundle manifest: {error}"))?;
    if manifest
        .get("schemaVersion")
        .and_then(|value| value.as_str())
        != Some(EXPORT_SCHEMA_VERSION)
    {
        return Err("unsupported Guardian bundle schema".into());
    }
    let profile = manifest
        .get("profile")
        .and_then(|value| value.as_str())
        .filter(|value| matches!(*value, "redacted" | "regression"))
        .ok_or_else(|| "invalid Guardian bundle profile".to_string())?;
    let case_id = manifest
        .get("caseId")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "Guardian bundle is missing caseId".to_string())?;
    validate_identifier(case_id, "case id")?;
    let files = manifest
        .get("files")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "Guardian bundle has no file manifest".to_string())?;
    if files.len() + 1 != archive.len() {
        return Err("Guardian bundle contains unmanifested files".into());
    }
    for expected in files {
        let name = expected
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "Guardian bundle file is missing a name".to_string())?;
        if name.contains('/') || name.contains('\\') || name == "manifest.json" {
            return Err("Guardian bundle contains an unsafe file name".into());
        }
        let expected_hash = expected
            .get("sha256")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "Guardian bundle file is missing a hash".to_string())?;
        let mut contents = Vec::new();
        archive
            .by_name(name)
            .map_err(|_| format!("Guardian bundle is missing {name}"))?
            .read_to_end(&mut contents)
            .map_err(|error| format!("failed to read Guardian bundle entry: {error}"))?;
        if hex::encode(Sha256::digest(&contents)) != expected_hash {
            return Err(format!("Guardian bundle hash mismatch for {name}"));
        }
    }
    Ok(GuardianCaseImportPreview {
        schema_version: EXPORT_SCHEMA_VERSION.into(),
        profile: profile.into(),
        case_id: case_id.into(),
        file_count: files.len(),
        verified: true,
    })
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

    #[test]
    fn imported_bundle_verifies_every_manifested_hash() {
        let payload = br#"{"case":{"caseId":"case-1"}}"#.to_vec();
        let files = vec![("case.json".to_string(), payload.clone())];
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": EXPORT_SCHEMA_VERSION,
            "profile": "redacted",
            "caseId": "case-1",
            "files": [{
                "name": "case.json",
                "sha256": hex::encode(Sha256::digest(&payload)),
                "size": payload.len(),
            }]
        }))
        .unwrap();
        let preview = import_guardian_case_bundle(ImportGuardianCaseInput {
            bytes: zip_bundle(&files, &manifest).unwrap(),
        })
        .unwrap();
        assert!(preview.verified);
        assert_eq!(preview.file_count, 1);

        let bad_manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": EXPORT_SCHEMA_VERSION,
            "profile": "redacted",
            "caseId": "case-1",
            "files": [{ "name": "case.json", "sha256": "0".repeat(64), "size": payload.len() }]
        }))
        .unwrap();
        let error = import_guardian_case_bundle(ImportGuardianCaseInput {
            bytes: zip_bundle(&files, &bad_manifest).unwrap(),
        })
        .unwrap_err();
        assert!(error.contains("hash mismatch"));
    }
}
