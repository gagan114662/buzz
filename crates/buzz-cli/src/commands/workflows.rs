use sha2::{Digest, Sha256};

use crate::client::{
    extract_d_tag, extract_relay_response_field, normalize_write_response, print_create_response,
    BuzzClient,
};
use crate::error::CliError;
use crate::validate::{parse_uuid, read_or_stdin, sdk_err, validate_uuid};

use super::parse_json_array_response;

// TODO(phase-4): Replace raw nostr::EventBuilder usage with buzz-sdk builder functions

/// List workflows in a channel — query kind:30620 workflow definition events.
pub async fn cmd_list_workflows(client: &BuzzClient, channel_id: &str) -> Result<(), CliError> {
    validate_uuid(channel_id)?;
    let filter = serde_json::json!({
        "kinds": [30620],
        "#h": [channel_id]
    });
    let resp = client.query(&filter).await?;
    let events = parse_json_array_response(&resp, "workflow query")?;
    let workflows: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "workflow_id": extract_d_tag(e),
                "content": e.get("content").and_then(|v| v.as_str()).unwrap_or(""),
                "created_at": e.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
                "pubkey": e.get("pubkey").and_then(|v| v.as_str()).unwrap_or(""),
            })
        })
        .collect();
    let output = serde_json::to_string(&workflows)
        .map_err(|error| CliError::Other(format!("workflow serialization failed: {error}")))?;
    println!("{output}");
    Ok(())
}

/// Get a single workflow definition.
pub async fn cmd_get_workflow(client: &BuzzClient, workflow_id: &str) -> Result<(), CliError> {
    validate_uuid(workflow_id)?;
    let filter = serde_json::json!({
        "kinds": [30620],
        "#d": [workflow_id]
    });
    let resp = client.query(&filter).await?;
    let events = parse_json_array_response(&resp, "workflow query")?;
    if let Some(e) = events.first() {
        let normalized = serde_json::json!({
            "workflow_id": extract_d_tag(e),
            "content": e.get("content").and_then(|v| v.as_str()).unwrap_or(""),
            "created_at": e.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
            "pubkey": e.get("pubkey").and_then(|v| v.as_str()).unwrap_or(""),
        });
        println!("{normalized}");
    } else {
        println!("null");
    }
    Ok(())
}

fn workflow_runs_path(workflow_id: &str, limit: Option<u32>) -> String {
    let limit = limit.unwrap_or(20).clamp(1, 100);
    format!("/api/workflows/{workflow_id}/runs?limit={limit}")
}

fn normalize_workflow_runs_response(response: &str) -> Result<String, CliError> {
    let runs: Vec<serde_json::Value> = serde_json::from_str(response)
        .map_err(|error| CliError::Other(format!("invalid workflow run response: {error}")))?;
    serde_json::to_string(&runs)
        .map_err(|error| CliError::Other(format!("workflow run serialization failed: {error}")))
}

/// Get authoritative workflow run history from the relay database.
pub async fn cmd_get_workflow_runs(
    client: &BuzzClient,
    workflow_id: &str,
    limit: Option<u32>,
) -> Result<(), CliError> {
    validate_uuid(workflow_id)?;
    let response = client
        .get_authed(&workflow_runs_path(workflow_id, limit))
        .await?;
    let output = normalize_workflow_runs_response(&response)?;
    println!("{output}");
    Ok(())
}

/// Create a workflow — sign and submit a kind:30620 event.
pub async fn cmd_create_workflow(
    client: &BuzzClient,
    channel_id: &str,
    yaml: &str,
) -> Result<(), CliError> {
    let channel_uuid = parse_uuid(channel_id)?;
    let yaml_definition = read_or_stdin(yaml)?;

    let workflow_id = uuid::Uuid::new_v4();
    let builder = buzz_sdk::build_workflow_def(channel_uuid, workflow_id, &yaml_definition)
        .map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    let final_workflow_id = validate_workflow_create_response(&resp, workflow_id)?;
    print_create_response(&resp, "workflow_id", &final_workflow_id);
    Ok(())
}

fn validate_workflow_create_response(
    resp: &str,
    expected_workflow_id: uuid::Uuid,
) -> Result<String, CliError> {
    let workflow_id = extract_relay_response_field(resp, "workflow_id").ok_or_else(|| {
        CliError::DeliveryUnknown(
            "workflow creation succeeded without a canonical workflow_id; outcome unknown".into(),
        )
    })?;
    let parsed = parse_uuid(&workflow_id).map_err(|_| {
        CliError::DeliveryUnknown(
            "workflow creation returned an invalid canonical workflow_id; outcome unknown".into(),
        )
    })?;
    if parsed != expected_workflow_id {
        return Err(CliError::DeliveryUnknown(
            "workflow creation returned a different workflow_id; outcome unknown".into(),
        ));
    }
    Ok(workflow_id)
}

/// Update a workflow — sign and submit an updated kind:30620 event with same d-tag.
pub async fn cmd_update_workflow(
    client: &BuzzClient,
    channel_id: &str,
    workflow_id: &str,
    yaml: &str,
) -> Result<(), CliError> {
    let channel_uuid = parse_uuid(channel_id)?;
    let wf_uuid = parse_uuid(workflow_id)?;
    let yaml_definition = read_or_stdin(yaml)?;

    let builder = buzz_sdk::build_workflow_update(channel_uuid, wf_uuid, &yaml_definition)
        .map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

/// Delete a workflow — sign and submit a kind:5 deletion event.
pub async fn cmd_delete_workflow(client: &BuzzClient, workflow_id: &str) -> Result<(), CliError> {
    let wf_uuid = parse_uuid(workflow_id)?;
    let keys = client.keys();

    let builder =
        buzz_sdk::build_workflow_delete(&keys.public_key().to_hex(), wf_uuid).map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

/// Trigger a workflow — sign and submit a kind:46020 event.
///
/// When `inputs` is provided, it is parsed as a JSON object and used as the
/// event content (MCP parity). When omitted, the event content is `{}`.
pub async fn cmd_trigger_workflow(
    client: &BuzzClient,
    workflow_id: &str,
    inputs: Option<&str>,
) -> Result<(), CliError> {
    let wf_uuid = parse_uuid(workflow_id)?;

    if let Some(raw) = inputs {
        // Parse and validate it is a JSON object, then build the event manually
        // so we can embed the inputs as the event content.
        let parsed: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| CliError::Usage(format!("--inputs is not valid JSON: {e}")))?;
        if !parsed.is_object() {
            return Err(CliError::Usage("--inputs must be a JSON object".into()));
        }
        let content = serde_json::to_string(&parsed).unwrap_or_default();
        use nostr::{EventBuilder, Kind, Tag};
        let tags = vec![Tag::parse(["d", &wf_uuid.to_string()])
            .map_err(|e| CliError::Other(format!("tag error: {e}")))?];
        let builder = EventBuilder::new(
            Kind::Custom(buzz_sdk::kind::KIND_WORKFLOW_TRIGGER as u16),
            &content,
        )
        .tags(tags);
        let event = client.sign_event(builder)?;
        let resp = client.submit_event(event).await?;
        print_workflow_trigger_response(&resp)?;
    } else {
        let builder = buzz_sdk::build_workflow_trigger(wf_uuid).map_err(sdk_err)?;
        let event = client.sign_event(builder)?;
        let resp = client.submit_event(event).await?;
        print_workflow_trigger_response(&resp)?;
    }
    Ok(())
}

fn print_workflow_trigger_response(resp: &str) -> Result<(), CliError> {
    let run_id = validate_workflow_trigger_response(resp)?;
    print_create_response(resp, "run_id", &run_id);
    Ok(())
}

fn validate_workflow_trigger_response(resp: &str) -> Result<String, CliError> {
    let run_id = extract_relay_response_field(resp, "run_id").ok_or_else(|| {
        CliError::DeliveryUnknown(
            "workflow trigger succeeded without a canonical run_id; outcome unknown".into(),
        )
    })?;
    parse_uuid(&run_id).map_err(|_| {
        CliError::DeliveryUnknown(
            "workflow trigger returned an invalid canonical run_id; outcome unknown".into(),
        )
    })?;
    Ok(run_id)
}

/// Approve or deny a workflow step — sign and submit a kind:46030 (grant) or 46031 (deny) event.
pub async fn cmd_approve_step(
    client: &BuzzClient,
    approval_token: &str,
    approved: bool,
    note: Option<&str>,
) -> Result<(), CliError> {
    validate_uuid(approval_token)?;

    let content = note.unwrap_or("");

    // The relay expects d-tag = hex(SHA256(token)), not the raw token UUID.
    let token_hash = hex::encode(Sha256::digest(approval_token.as_bytes()));
    let builder =
        buzz_sdk::build_workflow_approval(&token_hash, approved, content).map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

pub async fn dispatch(cmd: crate::WorkflowsCmd, client: &BuzzClient) -> Result<(), CliError> {
    use crate::WorkflowsCmd;
    match cmd {
        WorkflowsCmd::List { channel } => cmd_list_workflows(client, &channel).await,
        WorkflowsCmd::Get { workflow } => cmd_get_workflow(client, &workflow).await,
        WorkflowsCmd::Create { channel, yaml } => {
            cmd_create_workflow(client, &channel, &yaml).await
        }
        WorkflowsCmd::Update {
            channel,
            workflow,
            yaml,
        } => cmd_update_workflow(client, &channel, &workflow, &yaml).await,
        WorkflowsCmd::Delete { workflow } => cmd_delete_workflow(client, &workflow).await,
        WorkflowsCmd::Trigger { workflow, inputs } => {
            cmd_trigger_workflow(client, &workflow, inputs.as_deref()).await
        }
        WorkflowsCmd::Runs { workflow, limit } => {
            cmd_get_workflow_runs(client, &workflow, limit).await
        }
        WorkflowsCmd::Approve {
            token,
            approved,
            note,
        } => {
            // approved is already a bool — no parse_bool_flag needed
            cmd_approve_step(client, &token, approved, note.as_deref()).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_workflow_runs_response, validate_workflow_create_response,
        validate_workflow_trigger_response, workflow_runs_path,
    };

    const WORKFLOW_ID: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn workflow_runs_path_defaults_and_clamps_the_limit() {
        assert_eq!(
            workflow_runs_path(WORKFLOW_ID, None),
            format!("/api/workflows/{WORKFLOW_ID}/runs?limit=20")
        );
        assert_eq!(
            workflow_runs_path(WORKFLOW_ID, Some(0)),
            format!("/api/workflows/{WORKFLOW_ID}/runs?limit=1")
        );
        assert_eq!(
            workflow_runs_path(WORKFLOW_ID, Some(500)),
            format!("/api/workflows/{WORKFLOW_ID}/runs?limit=100")
        );
    }

    #[test]
    fn workflow_runs_response_preserves_authoritative_rows() {
        let response = r#"[{"id":"run-1","status":"succeeded","execution_trace":["step-a"]}]"#;
        let normalized = normalize_workflow_runs_response(response).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&normalized).unwrap(),
            serde_json::from_str::<serde_json::Value>(response).unwrap()
        );
    }

    #[test]
    fn workflow_runs_response_rejects_non_array_or_malformed_json() {
        assert!(normalize_workflow_runs_response(r#"{"id":"run-1"}"#).is_err());
        assert!(normalize_workflow_runs_response("not-json").is_err());
    }

    #[test]
    fn workflow_create_receipt_must_match_the_submitted_workflow_id() {
        let expected = uuid::Uuid::parse_str(WORKFLOW_ID).unwrap();
        let valid = format!(r#"{{"message":"response:{{\"workflow_id\":\"{WORKFLOW_ID}\"}}"}}"#);
        assert_eq!(
            validate_workflow_create_response(&valid, expected).unwrap(),
            WORKFLOW_ID
        );

        for invalid in [
            r#"{"message":"duplicate: already processed"}"#,
            r#"{"message":"response:{\"workflow_id\":\"not-a-uuid\"}"}"#,
            r#"{"message":"response:{\"workflow_id\":\"22222222-2222-4222-8222-222222222222\"}"}"#,
        ] {
            assert!(validate_workflow_create_response(invalid, expected).is_err());
        }
    }

    #[test]
    fn workflow_trigger_receipt_requires_a_canonical_run_id() {
        let run_id = "33333333-3333-4333-8333-333333333333";
        let valid = format!(r#"{{"message":"response:{{\"run_id\":\"{run_id}\"}}"}}"#);
        assert_eq!(validate_workflow_trigger_response(&valid).unwrap(), run_id);

        for invalid in [
            r#"{"message":"duplicate: already processed"}"#,
            r#"{"message":"response:{\"run_id\":\"not-a-uuid\"}"}"#,
        ] {
            assert!(validate_workflow_trigger_response(invalid).is_err());
        }
    }
}
