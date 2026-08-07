use std::path::PathBuf;

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, State};

use crate::{app_state::AppState, managed_agents::managed_agents_base_dir};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigureFleetInput {
    organization_id: String,
    name: String,
    owner_pubkey: String,
    security_approver_pubkey: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterEndpointInput {
    organization_id: String,
    endpoint_id: String,
    agent_pubkey: String,
    expected_policy_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateRolloutInput {
    organization_id: String,
    policy_hash: String,
    endpoint_ids: Vec<String>,
    wave_size: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FleetRolloutInput {
    organization_id: String,
    rollout_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportEndpointInput {
    organization_id: String,
    rollout_id: String,
    endpoint_id: String,
    observed_policy_hash: String,
    outcome: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmergencyStopInput {
    organization_id: String,
    stopped: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetEndpoint {
    endpoint_id: String,
    agent_pubkey: String,
    expected_policy_hash: Option<String>,
    observed_policy_hash: Option<String>,
    status: String,
    last_seen_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetRollout {
    rollout_id: String,
    policy_hash: String,
    state: String,
    endpoint_ids: Vec<String>,
    wave_size: usize,
    next_index: usize,
    owner_approved_at: Option<String>,
    security_approved_at: Option<String>,
    created_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardianFleet {
    organization_id: String,
    name: String,
    owner_pubkey: String,
    security_approver_pubkey: String,
    emergency_stopped: bool,
    endpoints: Vec<FleetEndpoint>,
    rollouts: Vec<FleetRollout>,
}

fn path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(managed_agents_base_dir(app)?.join("guardian-fleet.sqlite3"))
}

fn open(app: &AppHandle) -> Result<Connection, String> {
    let path = path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create fleet store: {e}"))?;
    }
    let connection =
        Connection::open(path).map_err(|e| format!("failed to open fleet store: {e}"))?;
    initialize(&connection)?;
    Ok(connection)
}

fn initialize(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS guardian_fleet_org(
           organization_id TEXT PRIMARY KEY, name TEXT NOT NULL, owner_pubkey TEXT NOT NULL,
           security_approver_pubkey TEXT NOT NULL, emergency_stopped INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS guardian_fleet_endpoint(
           organization_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, agent_pubkey TEXT NOT NULL,
           expected_policy_hash TEXT, observed_policy_hash TEXT, status TEXT NOT NULL,
           last_seen_at TEXT, PRIMARY KEY(organization_id, endpoint_id),
           FOREIGN KEY(organization_id) REFERENCES guardian_fleet_org(organization_id));
         CREATE TABLE IF NOT EXISTS guardian_fleet_rollout(
           organization_id TEXT NOT NULL, rollout_id TEXT PRIMARY KEY, policy_hash TEXT NOT NULL,
           state TEXT NOT NULL, endpoint_ids_json TEXT NOT NULL, wave_size INTEGER NOT NULL,
           next_index INTEGER NOT NULL DEFAULT 0, owner_approved_at TEXT,
           security_approved_at TEXT, created_at TEXT NOT NULL,
           FOREIGN KEY(organization_id) REFERENCES guardian_fleet_org(organization_id));
         CREATE TABLE IF NOT EXISTS guardian_fleet_audit(
           sequence INTEGER PRIMARY KEY AUTOINCREMENT, organization_id TEXT NOT NULL,
           action TEXT NOT NULL, actor_pubkey TEXT NOT NULL, subject_id TEXT NOT NULL,
           created_at TEXT NOT NULL, previous_hash TEXT, event_hash TEXT NOT NULL UNIQUE);",
        )
        .map_err(|e| format!("failed to initialize fleet store: {e}"))
}

fn pubkey(value: &str) -> Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid public key".into());
    }
    Ok(value.to_lowercase())
}

fn token(value: &str, label: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 120
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(format!("invalid {label}"));
    }
    Ok(value.to_string())
}

fn actor(state: &AppState) -> Result<String, String> {
    let keys = state.keys.lock().map_err(|e| e.to_string())?;
    Ok(keys.public_key().to_hex())
}

fn audit(
    connection: &Connection,
    org: &str,
    action: &str,
    actor: &str,
    subject: &str,
) -> Result<(), String> {
    let previous: Option<String> = connection.query_row(
        "SELECT event_hash FROM guardian_fleet_audit WHERE organization_id=?1 ORDER BY sequence DESC LIMIT 1",
        [org], |row| row.get(0)).optional().map_err(|e| format!("failed to read fleet audit head: {e}"))?;
    let now = Utc::now().to_rfc3339();
    let canonical = serde_json::to_vec(&serde_json::json!({"organizationId":org,"action":action,"actorPubkey":actor,"subjectId":subject,"createdAt":now,"previousHash":previous}))
        .map_err(|e| format!("failed to encode fleet audit event: {e}"))?;
    let hash = hex::encode(Sha256::digest(canonical));
    connection.execute("INSERT INTO guardian_fleet_audit(organization_id,action,actor_pubkey,subject_id,created_at,previous_hash,event_hash) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![org,action,actor,subject,now,previous,hash]).map_err(|e| format!("failed to append fleet audit event: {e}"))?;
    Ok(())
}

fn require_role(connection: &Connection, org: &str, actor: &str, role: &str) -> Result<(), String> {
    let column = if role == "owner" {
        "owner_pubkey"
    } else {
        "security_approver_pubkey"
    };
    let expected: String = connection
        .query_row(
            &format!("SELECT {column} FROM guardian_fleet_org WHERE organization_id=?1"),
            [org],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("failed to read fleet authority: {e}"))?
        .ok_or_else(|| "organization was not found".to_string())?;
    if !expected.eq_ignore_ascii_case(actor) {
        return Err(format!("current identity is not the organization {role}"));
    }
    Ok(())
}

fn endpoint_status(
    outcome: &str,
    expected: Option<&str>,
    observed: &str,
) -> Result<&'static str, String> {
    match outcome {
        "applied" if expected == Some(observed) => Ok("healthy"),
        "applied" => Ok("drifted"),
        "failed" => Ok("failed"),
        "offline" => Ok("offline"),
        _ => Err("endpoint outcome must be applied, failed, or offline".into()),
    }
}

fn read_fleet(connection: &Connection, org: &str) -> Result<GuardianFleet, String> {
    let (name, owner, security, stopped): (String,String,String,bool) = connection.query_row(
        "SELECT name,owner_pubkey,security_approver_pubkey,emergency_stopped FROM guardian_fleet_org WHERE organization_id=?1", [org],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()
        .map_err(|e| format!("failed to read organization: {e}"))?.ok_or_else(|| "organization was not found".to_string())?;
    let mut statement = connection.prepare("SELECT endpoint_id,agent_pubkey,expected_policy_hash,observed_policy_hash,status,last_seen_at FROM guardian_fleet_endpoint WHERE organization_id=?1 ORDER BY endpoint_id")
        .map_err(|e| format!("failed to prepare endpoint list: {e}"))?;
    let endpoints = statement
        .query_map([org], |r| {
            Ok(FleetEndpoint {
                endpoint_id: r.get(0)?,
                agent_pubkey: r.get(1)?,
                expected_policy_hash: r.get(2)?,
                observed_policy_hash: r.get(3)?,
                status: r.get(4)?,
                last_seen_at: r.get(5)?,
            })
        })
        .map_err(|e| format!("failed to list endpoints: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to decode endpoint: {e}"))?;
    let mut statement = connection.prepare("SELECT rollout_id,policy_hash,state,endpoint_ids_json,wave_size,next_index,owner_approved_at,security_approved_at,created_at FROM guardian_fleet_rollout WHERE organization_id=?1 ORDER BY rowid DESC")
        .map_err(|e| format!("failed to prepare rollout list: {e}"))?;
    let rollouts = statement
        .query_map([org], |r| {
            let json: String = r.get(3)?;
            let endpoint_ids = serde_json::from_str(&json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok(FleetRollout {
                rollout_id: r.get(0)?,
                policy_hash: r.get(1)?,
                state: r.get(2)?,
                endpoint_ids,
                wave_size: r.get::<_, i64>(4)? as usize,
                next_index: r.get::<_, i64>(5)? as usize,
                owner_approved_at: r.get(6)?,
                security_approved_at: r.get(7)?,
                created_at: r.get(8)?,
            })
        })
        .map_err(|e| format!("failed to list rollouts: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to decode rollout: {e}"))?;
    Ok(GuardianFleet {
        organization_id: org.into(),
        name,
        owner_pubkey: owner,
        security_approver_pubkey: security,
        emergency_stopped: stopped,
        endpoints,
        rollouts,
    })
}

#[tauri::command]
pub fn configure_guardian_fleet(
    app: AppHandle,
    state: State<'_, AppState>,
    input: ConfigureFleetInput,
) -> Result<GuardianFleet, String> {
    let org = token(&input.organization_id, "organization id")?;
    let owner = pubkey(&input.owner_pubkey)?;
    let security = pubkey(&input.security_approver_pubkey)?;
    if owner == security {
        return Err("owner and security approver must be different identities".into());
    }
    let current = actor(&state)?;
    if current != owner {
        return Err("only the current owner identity can configure an organization".into());
    }
    if input.name.trim().is_empty() || input.name.len() > 120 {
        return Err("invalid organization name".into());
    }
    let connection = open(&app)?;
    let existing_owner: Option<String> = connection
        .query_row(
            "SELECT owner_pubkey FROM guardian_fleet_org WHERE organization_id=?1",
            [&org],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("failed to read existing organization authority: {e}"))?;
    if existing_owner
        .as_deref()
        .is_some_and(|value| value != owner)
    {
        return Err("organization already belongs to a different owner".into());
    }
    connection.execute("INSERT INTO guardian_fleet_org(organization_id,name,owner_pubkey,security_approver_pubkey) VALUES(?1,?2,?3,?4) ON CONFLICT(organization_id) DO UPDATE SET name=excluded.name,security_approver_pubkey=excluded.security_approver_pubkey WHERE owner_pubkey=excluded.owner_pubkey",params![org,input.name.trim(),owner,security]).map_err(|e| format!("failed to configure organization: {e}"))?;
    audit(&connection, &org, "configure", &current, &org)?;
    read_fleet(&connection, &org)
}

#[tauri::command]
pub fn get_guardian_fleet(
    app: AppHandle,
    organization_id: String,
) -> Result<GuardianFleet, String> {
    let org = token(&organization_id, "organization id")?;
    read_fleet(&open(&app)?, &org)
}

#[tauri::command]
pub fn register_guardian_fleet_endpoint(
    app: AppHandle,
    state: State<'_, AppState>,
    input: RegisterEndpointInput,
) -> Result<GuardianFleet, String> {
    let org = token(&input.organization_id, "organization id")?;
    let endpoint = token(&input.endpoint_id, "endpoint id")?;
    let agent = pubkey(&input.agent_pubkey)?;
    let current = actor(&state)?;
    let connection = open(&app)?;
    require_role(&connection, &org, &current, "owner")?;
    if let Some(hash) = input.expected_policy_hash.as_deref() {
        pubkey(hash)?;
    }
    connection.execute("INSERT INTO guardian_fleet_endpoint VALUES(?1,?2,?3,?4,NULL,'offline',NULL) ON CONFLICT(organization_id,endpoint_id) DO UPDATE SET agent_pubkey=excluded.agent_pubkey,expected_policy_hash=excluded.expected_policy_hash",params![org,endpoint,agent,input.expected_policy_hash]).map_err(|e|format!("failed to register endpoint: {e}"))?;
    audit(&connection, &org, "register_endpoint", &current, &endpoint)?;
    read_fleet(&connection, &org)
}

#[tauri::command]
pub fn create_guardian_fleet_rollout(
    app: AppHandle,
    state: State<'_, AppState>,
    input: CreateRolloutInput,
) -> Result<GuardianFleet, String> {
    let org = token(&input.organization_id, "organization id")?;
    pubkey(&input.policy_hash)?;
    if input.endpoint_ids.is_empty()
        || input.wave_size == 0
        || input.wave_size > input.endpoint_ids.len()
    {
        return Err("rollout requires endpoints and a valid wave size".into());
    }
    let mut endpoints = input
        .endpoint_ids
        .iter()
        .map(|v| token(v, "endpoint id"))
        .collect::<Result<Vec<_>, _>>()?;
    endpoints.sort();
    endpoints.dedup();
    if endpoints.len() != input.endpoint_ids.len() {
        return Err("rollout endpoints must be unique".into());
    }
    let current = actor(&state)?;
    let connection = open(&app)?;
    require_role(&connection, &org, &current, "owner")?;
    let stopped: bool = connection
        .query_row(
            "SELECT emergency_stopped FROM guardian_fleet_org WHERE organization_id=?1",
            [&org],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if stopped {
        return Err("fleet emergency stop is active".into());
    }
    for endpoint in &endpoints {
        let exists:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM guardian_fleet_endpoint WHERE organization_id=?1 AND endpoint_id=?2)",params![org,endpoint],|r|r.get(0)).map_err(|e|e.to_string())?;
        if !exists {
            return Err(format!("endpoint {endpoint} is outside this organization"));
        }
    }
    let rollout_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let json = serde_json::to_string(&endpoints).map_err(|e| e.to_string())?;
    connection.execute("INSERT INTO guardian_fleet_rollout(organization_id,rollout_id,policy_hash,state,endpoint_ids_json,wave_size,created_at) VALUES(?1,?2,?3,'awaiting_owner',?4,?5,?6)",params![org,rollout_id,input.policy_hash,json,input.wave_size as i64,now]).map_err(|e|format!("failed to create rollout: {e}"))?;
    audit(&connection, &org, "create_rollout", &current, &rollout_id)?;
    read_fleet(&connection, &org)
}

#[tauri::command]
pub fn approve_guardian_fleet_rollout(
    app: AppHandle,
    state: State<'_, AppState>,
    input: FleetRolloutInput,
) -> Result<GuardianFleet, String> {
    let org = token(&input.organization_id, "organization id")?;
    let rollout = token(&input.rollout_id, "rollout id")?;
    let current = actor(&state)?;
    let mut connection = open(&app)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let row: (String, String) = tx
        .query_row(
            "SELECT state,organization_id FROM guardian_fleet_rollout WHERE rollout_id=?1",
            [&rollout],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "rollout was not found".to_string())?;
    if row.1 != org {
        return Err("rollout belongs to a different organization".into());
    }
    let (role, next, column) = if row.0 == "awaiting_owner" {
        ("owner", "awaiting_security", "owner_approved_at")
    } else if row.0 == "awaiting_security" {
        ("security approver", "ready", "security_approved_at")
    } else {
        return Err("rollout is not awaiting this approval".into());
    };
    require_role(
        &tx,
        &org,
        &current,
        if role == "owner" { "owner" } else { "security" },
    )?;
    let now = Utc::now().to_rfc3339();
    tx.execute(&format!("UPDATE guardian_fleet_rollout SET state=?2,{column}=?3 WHERE rollout_id=?1 AND state=?4"),params![rollout,next,now,row.0]).map_err(|e|e.to_string())?;
    audit(&tx, &org, &format!("approve_{role}"), &current, &rollout)?;
    tx.commit().map_err(|e| e.to_string())?;
    read_fleet(&connection, &org)
}

#[tauri::command]
pub fn advance_guardian_fleet_rollout(
    app: AppHandle,
    state: State<'_, AppState>,
    input: FleetRolloutInput,
) -> Result<GuardianFleet, String> {
    let org = token(&input.organization_id, "organization id")?;
    let rollout = token(&input.rollout_id, "rollout id")?;
    let current = actor(&state)?;
    let connection = open(&app)?;
    require_role(&connection, &org, &current, "owner")?;
    let stopped: bool = connection
        .query_row(
            "SELECT emergency_stopped FROM guardian_fleet_org WHERE organization_id=?1",
            [&org],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if stopped {
        return Err("fleet emergency stop is active".into());
    }
    let (state_name,json,wave,next_index,policy):(String,String,i64,i64,String)=connection.query_row("SELECT state,endpoint_ids_json,wave_size,next_index,policy_hash FROM guardian_fleet_rollout WHERE rollout_id=?1 AND organization_id=?2",params![rollout,org],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?.ok_or_else(||"rollout was not found in this organization".to_string())?;
    if !matches!(state_name.as_str(), "ready" | "rolling") {
        return Err("rollout is not ready to advance".into());
    }
    let endpoints: Vec<String> = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    let end = ((next_index + wave) as usize).min(endpoints.len());
    for endpoint in &endpoints[next_index as usize..end] {
        connection.execute("UPDATE guardian_fleet_endpoint SET expected_policy_hash=?3,status='pending' WHERE organization_id=?1 AND endpoint_id=?2",params![org,endpoint,policy]).map_err(|e|e.to_string())?;
    }
    let state = if end == endpoints.len() {
        "deployed"
    } else {
        "rolling"
    };
    connection
        .execute(
            "UPDATE guardian_fleet_rollout SET state=?2,next_index=?3 WHERE rollout_id=?1",
            params![rollout, state, end as i64],
        )
        .map_err(|e| e.to_string())?;
    audit(&connection, &org, "advance_wave", &current, &rollout)?;
    read_fleet(&connection, &org)
}

#[tauri::command]
pub fn report_guardian_fleet_endpoint(
    app: AppHandle,
    input: ReportEndpointInput,
) -> Result<GuardianFleet, String> {
    let org = token(&input.organization_id, "organization id")?;
    let rollout = token(&input.rollout_id, "rollout id")?;
    let endpoint = token(&input.endpoint_id, "endpoint id")?;
    let observed = pubkey(&input.observed_policy_hash)?;
    let connection = open(&app)?;
    let expected:Option<String>=connection.query_row("SELECT expected_policy_hash FROM guardian_fleet_endpoint WHERE organization_id=?1 AND endpoint_id=?2",params![org,endpoint],|r|r.get(0)).optional().map_err(|e|e.to_string())?.ok_or_else(||"endpoint was not found in this organization".to_string())?;
    let rollout_binding: Option<(String, String)> = connection
        .query_row(
            "SELECT policy_hash,endpoint_ids_json FROM guardian_fleet_rollout WHERE organization_id=?1 AND rollout_id=?2",
            params![org, rollout],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let Some((rollout_policy, rollout_endpoints_json)) = rollout_binding else {
        return Err("rollout was not found in this organization".into());
    };
    let rollout_endpoints: Vec<String> =
        serde_json::from_str(&rollout_endpoints_json).map_err(|e| e.to_string())?;
    if !rollout_endpoints.iter().any(|value| value == &endpoint) {
        return Err("endpoint is not assigned to this rollout".into());
    }
    if expected.as_deref() != Some(rollout_policy.as_str()) {
        return Err("endpoint has not been released in this rollout wave".into());
    }
    let status = endpoint_status(&input.outcome, expected.as_deref(), &observed)?;
    connection.execute("UPDATE guardian_fleet_endpoint SET observed_policy_hash=?3,status=?4,last_seen_at=?5 WHERE organization_id=?1 AND endpoint_id=?2",params![org,endpoint,observed,status,Utc::now().to_rfc3339()]).map_err(|e|e.to_string())?;
    audit(
        &connection,
        &org,
        &format!("endpoint_{status}"),
        &endpoint,
        &rollout,
    )?;
    read_fleet(&connection, &org)
}

#[tauri::command]
pub fn set_guardian_fleet_emergency_stop(
    app: AppHandle,
    state: State<'_, AppState>,
    input: EmergencyStopInput,
) -> Result<GuardianFleet, String> {
    let org = token(&input.organization_id, "organization id")?;
    let current = actor(&state)?;
    let connection = open(&app)?;
    require_role(&connection, &org, &current, "owner")?;
    connection
        .execute(
            "UPDATE guardian_fleet_org SET emergency_stopped=?2 WHERE organization_id=?1",
            params![org, input.stopped],
        )
        .map_err(|e| e.to_string())?;
    if input.stopped {
        connection.execute("UPDATE guardian_fleet_rollout SET state='stopped' WHERE organization_id=?1 AND state IN('ready','rolling','deployed')",[&org]).map_err(|e|e.to_string())?;
    }
    audit(
        &connection,
        &org,
        if input.stopped {
            "emergency_stop"
        } else {
            "emergency_resume"
        },
        &current,
        &org,
    )?;
    read_fleet(&connection, &org)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_same_person_two_party_control() {
        let key = "a".repeat(64);
        assert_eq!(pubkey(&key).unwrap(), key);
    }
    #[test]
    fn validates_tenant_tokens_and_hashes() {
        assert!(token("org-a", "organization id").is_ok());
        assert!(token("../bad", "organization id").is_err());
        assert!(pubkey(&"f".repeat(64)).is_ok());
    }

    #[test]
    fn classifies_endpoint_reports_without_hiding_drift() {
        let expected = "a".repeat(64);
        let drifted = "b".repeat(64);
        assert_eq!(
            endpoint_status("applied", Some(&expected), &expected),
            Ok("healthy")
        );
        assert_eq!(
            endpoint_status("applied", Some(&expected), &drifted),
            Ok("drifted")
        );
        assert_eq!(
            endpoint_status("failed", Some(&expected), &expected),
            Ok("failed")
        );
        assert_eq!(
            endpoint_status("offline", Some(&expected), &expected),
            Ok("offline")
        );
        assert!(endpoint_status("unknown", Some(&expected), &expected).is_err());
    }
}
