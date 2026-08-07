use std::path::PathBuf;

use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, State};

use crate::{
    app_state::AppState,
    durable_tasks::{
        logical_effect_key, DurableTaskCore, DurableTaskStore, EffectRecord, EffectState,
        HandoffRecord, TaskBindings, TaskBudget, TaskLease, TaskStatus, TASK_SCHEMA_VERSION,
    },
    managed_agents::managed_agents_base_dir,
};

const SIMULATION_TASK_ID: &str = "synthetic-monthly-close";
const SIMULATION_EFFECT_STEP: &str = "publish-close-packet";
const SIMULATION_EFFECT_ID: &str = "owner-delivery";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableRecoveryView {
    task: DurableTaskCore,
    revision_hash: String,
    effect: EffectRecord,
    lease: Option<TaskLease>,
    handoffs: Vec<HandoffRecord>,
    recovery_state: String,
    synthetic: bool,
}

fn path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(managed_agents_base_dir(app)?.join("guardian-durable-tasks.sqlite3"))
}

fn open(app: &AppHandle) -> Result<Connection, String> {
    let path = path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create durable task directory: {e}"))?;
    }
    let mut connection =
        Connection::open(path).map_err(|e| format!("failed to open durable task store: {e}"))?;
    DurableTaskStore::new(&mut connection)?;
    Ok(connection)
}

fn actor(state: &AppState) -> Result<String, String> {
    let keys = state.keys.lock().map_err(|e| e.to_string())?;
    Ok(keys.public_key().to_hex())
}

fn hash(label: &str) -> String {
    hex::encode(Sha256::digest(label.as_bytes()))
}

fn read_view(connection: &mut Connection) -> Result<DurableRecoveryView, String> {
    let effect_key = logical_effect_key(
        SIMULATION_TASK_ID,
        SIMULATION_EFFECT_STEP,
        SIMULATION_EFFECT_ID,
    );
    let (task, revision_hash, effect) = {
        let store = DurableTaskStore::new(connection)?;
        let (task, revision_hash) = store
            .load_head(SIMULATION_TASK_ID)?
            .ok_or_else(|| "synthetic durable task was not found".to_string())?;
        let effect = store
            .load_effect(&effect_key)?
            .ok_or_else(|| "synthetic durable effect was not found".to_string())?;
        (task, revision_hash, effect)
    };
    let lease = connection
        .query_row(
            "SELECT task_id,holder,generation,expires_at FROM guardian_durable_task_lease WHERE task_id=?1",
            [SIMULATION_TASK_ID],
            |row| {
                Ok(TaskLease {
                    task_id: row.get(0)?,
                    holder: row.get(1)?,
                    generation: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|e| format!("failed to read durable task lease: {e}"))?;
    let mut statement = connection
        .prepare(
            "SELECT handoff_id,task_id,task_revision_hash,from_actor,to_actor,next_permitted_step,expires_at,accepted_revision_hash FROM guardian_durable_handoff WHERE task_id=?1 ORDER BY rowid",
        )
        .map_err(|e| format!("failed to prepare durable handoff list: {e}"))?;
    let handoffs = statement
        .query_map([SIMULATION_TASK_ID], |row| {
            Ok(HandoffRecord {
                handoff_id: row.get(0)?,
                task_id: row.get(1)?,
                task_revision_hash: row.get(2)?,
                from_actor: row.get(3)?,
                to_actor: row.get(4)?,
                next_permitted_step: row.get(5)?,
                expires_at: row.get(6)?,
                accepted_revision_hash: row.get(7)?,
            })
        })
        .map_err(|e| format!("failed to list durable handoffs: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to decode durable handoff: {e}"))?;
    let recovery_state = match (task.status, effect.state) {
        (TaskStatus::Complete, _) => "complete",
        (TaskStatus::ReadyForDelivery, EffectState::Observed) => "ready_for_delivery",
        (TaskStatus::Validating, EffectState::Indeterminate) => "recovered_needs_reconciliation",
        (_, EffectState::Indeterminate) => "crashed_effect_unknown",
        _ => "in_progress",
    }
    .to_string();
    Ok(DurableRecoveryView {
        task,
        revision_hash,
        effect,
        lease,
        handoffs,
        recovery_state,
        synthetic: true,
    })
}

#[tauri::command]
pub fn seed_guardian_durable_recovery_simulation(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DurableRecoveryView, String> {
    let owner = actor(&state)?;
    let reviewer = hash(&format!("{owner}:synthetic-independent-reviewer"));
    let now = Utc::now();
    let authority_expiry = (now + Duration::days(1)).to_rfc3339();
    let mut connection = open(&app)?;
    connection
        .execute(
            "DELETE FROM guardian_durable_effect WHERE task_id=?1",
            [SIMULATION_TASK_ID],
        )
        .map_err(|e| e.to_string())?;
    connection
        .execute(
            "DELETE FROM guardian_durable_handoff WHERE task_id=?1",
            [SIMULATION_TASK_ID],
        )
        .map_err(|e| e.to_string())?;
    connection
        .execute(
            "DELETE FROM guardian_durable_task_lease WHERE task_id=?1",
            [SIMULATION_TASK_ID],
        )
        .map_err(|e| e.to_string())?;
    connection
        .execute(
            "DELETE FROM guardian_durable_task_head WHERE task_id=?1",
            [SIMULATION_TASK_ID],
        )
        .map_err(|e| e.to_string())?;
    connection
        .execute(
            "DELETE FROM guardian_durable_task_revision WHERE task_id=?1",
            [SIMULATION_TASK_ID],
        )
        .map_err(|e| e.to_string())?;

    {
        let mut store = DurableTaskStore::new(&mut connection)?;
        let first = DurableTaskCore {
            schema_version: TASK_SCHEMA_VERSION.into(),
            task_id: SIMULATION_TASK_ID.into(),
            revision: 1,
            previous_revision_hash: None,
            status: TaskStatus::Running,
            owner_pubkey: owner.clone(),
            actor_pubkey: owner.clone(),
            authority_grant_id: "synthetic-owner-grant".into(),
            authority_expires_at: authority_expiry.clone(),
            bindings: TaskBindings {
                policy_hash: hash("synthetic-policy"),
                sandbox_profile_hash: hash("synthetic-disposable-sandbox"),
                runtime_attestation_hash: hash("synthetic-runtime-attestation"),
                runtime_attestation_expires_at: authority_expiry.clone(),
                execution_locus: "synthetic-local-macos-vm".into(),
            },
            budget: TaskBudget {
                token_limit: Some(100_000),
                cost_limit_microusd: Some(5_000_000),
                wall_deadline: Some(authority_expiry.clone()),
                consumed_tokens: 12_500,
                consumed_microusd: 420_000,
            },
            input_hashes: vec![hash("synthetic-monthly-close-input")],
            artifact_hashes: vec![hash("synthetic-close-packet")],
            unresolved_blocking_decisions: Vec::new(),
        };
        let first_hash = store.create(&first)?;
        let handoff = store.create_handoff(
            SIMULATION_TASK_ID,
            &first_hash,
            &reviewer,
            "independently-review-close-packet",
            &authority_expiry,
            now,
        )?;
        let mut reviewed = first.clone();
        reviewed.revision = 2;
        reviewed.previous_revision_hash = Some(first_hash);
        reviewed.actor_pubkey = reviewer.clone();
        reviewed.authority_grant_id = "synthetic-reviewer-grant".into();
        store.accept_handoff(&handoff.handoff_id, &reviewer, &reviewed, now)?;
        let effect = store.prepare_effect(
            SIMULATION_TASK_ID,
            SIMULATION_EFFECT_STEP,
            SIMULATION_EFFECT_ID,
            b"synthetic close packet delivery",
        )?;
        store.mark_effect_pending(&effect.effect_key)?;
        store.mark_effect_indeterminate(&effect.effect_key)?;
        store.acquire_lease(
            SIMULATION_TASK_ID,
            "synthetic-crashed-worker",
            &(now + Duration::minutes(5)).to_rfc3339(),
            now,
        )?;
    }
    connection
        .execute(
            "UPDATE guardian_durable_task_lease SET expires_at=?2 WHERE task_id=?1",
            params![
                SIMULATION_TASK_ID,
                (now - Duration::minutes(1)).to_rfc3339()
            ],
        )
        .map_err(|e| e.to_string())?;
    read_view(&mut connection)
}

#[tauri::command]
pub fn get_guardian_durable_recovery_simulation(
    app: AppHandle,
) -> Result<DurableRecoveryView, String> {
    read_view(&mut open(&app)?)
}

#[tauri::command]
pub fn recover_guardian_durable_simulation(app: AppHandle) -> Result<DurableRecoveryView, String> {
    let now = Utc::now();
    let mut connection = open(&app)?;
    {
        let mut store = DurableTaskStore::new(&mut connection)?;
        store.acquire_lease(
            SIMULATION_TASK_ID,
            "synthetic-recovery-worker",
            &(now + Duration::minutes(15)).to_rfc3339(),
            now,
        )?;
        let (current, head) = store
            .load_head(SIMULATION_TASK_ID)?
            .ok_or_else(|| "synthetic durable task was not found".to_string())?;
        let mut next = current.clone();
        next.revision += 1;
        next.previous_revision_hash = Some(head.clone());
        next.status = TaskStatus::Validating;
        store.compare_and_swap(&head, &next)?;
    }
    read_view(&mut connection)
}

#[tauri::command]
pub fn reconcile_guardian_durable_simulation(
    app: AppHandle,
) -> Result<DurableRecoveryView, String> {
    let mut connection = open(&app)?;
    {
        let mut store = DurableTaskStore::new(&mut connection)?;
        let effect_key = logical_effect_key(
            SIMULATION_TASK_ID,
            SIMULATION_EFFECT_STEP,
            SIMULATION_EFFECT_ID,
        );
        store.reconcile_indeterminate_effect(
            &effect_key,
            b"synthetic provider receipt: delivery observed exactly once",
        )?;
        let (current, head) = store
            .load_head(SIMULATION_TASK_ID)?
            .ok_or_else(|| "synthetic durable task was not found".to_string())?;
        if current.status != TaskStatus::Validating {
            return Err("recover the crashed task before reconciling its effect".into());
        }
        let mut next = current.clone();
        next.revision += 1;
        next.previous_revision_hash = Some(head.clone());
        next.status = TaskStatus::ReadyForDelivery;
        next.validate_delivery(true)?;
        store.compare_and_swap(&head, &next)?;
    }
    read_view(&mut connection)
}

#[tauri::command]
pub fn complete_guardian_durable_simulation(app: AppHandle) -> Result<DurableRecoveryView, String> {
    let mut connection = open(&app)?;
    {
        let mut store = DurableTaskStore::new(&mut connection)?;
        let effect_key = logical_effect_key(
            SIMULATION_TASK_ID,
            SIMULATION_EFFECT_STEP,
            SIMULATION_EFFECT_ID,
        );
        let effect = store
            .load_effect(&effect_key)?
            .ok_or_else(|| "synthetic durable effect was not found".to_string())?;
        if effect.state != EffectState::Observed {
            return Err("delivery effect has not been reconciled".into());
        }
        let (current, head) = store
            .load_head(SIMULATION_TASK_ID)?
            .ok_or_else(|| "synthetic durable task was not found".to_string())?;
        current.validate_delivery(true)?;
        let mut next = current.clone();
        next.revision += 1;
        next.previous_revision_hash = Some(head.clone());
        next.status = TaskStatus::Complete;
        store.compare_and_swap(&head, &next)?;
    }
    read_view(&mut connection)
}
