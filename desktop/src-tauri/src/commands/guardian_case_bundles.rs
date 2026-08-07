use std::io::{Cursor, Read as _, Write as _};

use super::*;

pub(super) const EXPORT_SCHEMA_VERSION: &str = "guardian.case-export/v1";

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportGuardianCaseInput {
    case_id: String,
    profile: String,
    destination_label: Option<String>,
    owner_confirmed_secrets: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportGuardianCaseInput {
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardianCaseImportPreview {
    pub(super) schema_version: String,
    pub(super) profile: String,
    pub(super) case_id: String,
    pub(super) file_count: usize,
    pub(super) verified: bool,
}

pub(super) fn zip_bundle(files: &[(String, Vec<u8>)], manifest: &[u8]) -> Result<Vec<u8>, String> {
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
    if !matches!(input.profile.as_str(), "redacted" | "regression" | "full") {
        return Err("invalid Guardian case export profile".into());
    }
    if input.profile == "full" {
        if input.owner_confirmed_secrets != Some(true) {
            return Err(
                "full forensic export requires fresh confirmation that secrets may be present"
                    .into(),
            );
        }
        validate_text_label(
            input.destination_label.as_deref().unwrap_or_default(),
            "export destination",
            160,
        )?;
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
    let payload = if input.profile == "redacted" || input.profile == "full" {
        serde_json::json!({ "case": case, "findings": findings })
    } else {
        serde_json::json!({
            "fixtureSchemaVersion": "guardian.regression-fixture/v1",
            "expectedFindings": findings.iter().map(|finding| serde_json::json!({
                "ruleId": finding["ruleId"], "severity": finding["severity"]
            })).collect::<Vec<_>>()
        })
    };
    let entry_name = if input.profile == "redacted" || input.profile == "full" {
        "case.json"
    } else {
        "fixture.json"
    };
    let payload_bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|error| format!("failed to encode Guardian export payload: {error}"))?;
    let mut files = vec![(entry_name.to_string(), payload_bytes)];
    if input.profile == "full" {
        let mut selected = Vec::new();
        let evidence_dir = managed_agents_base_dir(&app)?.join("guardian-evidence");
        for finding_id in &case.finding_ids {
            let mut statement = connection
                .prepare(
                    "SELECT blob_hash, relative_path, size_bytes FROM guardian_evidence_blob
                 WHERE finding_id = ?1 ORDER BY created_at",
                )
                .map_err(|error| format!("failed to prepare Guardian evidence export: {error}"))?;
            let rows = statement
                .query_map([finding_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|error| format!("failed to list Guardian evidence blobs: {error}"))?;
            for row in rows {
                let (expected_hash, relative_path, expected_size) = row
                    .map_err(|error| format!("failed to read Guardian evidence index: {error}"))?;
                if relative_path.contains('/') || relative_path.contains('\\') {
                    return Err("Guardian evidence index contains an unsafe path".into());
                }
                let bytes = std::fs::read(evidence_dir.join(relative_path)).map_err(|error| {
                    format!("failed to read immutable Guardian evidence: {error}")
                })?;
                if bytes.len() as i64 != expected_size
                    || hex::encode(Sha256::digest(&bytes)) != expected_hash
                {
                    return Err("immutable Guardian evidence failed integrity verification".into());
                }
                selected.extend_from_slice(&bytes);
                selected.push(b'\n');
            }
        }
        if selected.is_empty() {
            return Err("no immutable local Numbat evidence remains for this case".into());
        }
        files.push(("evidence.ndjson".into(), selected));
    }
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
        "destinationLabel": input.destination_label,
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

fn validate_text_label(value: &str, label: &str, max: usize) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > max || trimmed.chars().any(char::is_control)
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

#[tauri::command]
pub async fn save_guardian_case_bundle(
    app: AppHandle,
    input: ExportGuardianCaseInput,
) -> Result<bool, String> {
    let bytes = export_guardian_case_bundle(app.clone(), input.clone())?;
    let filename = format!("guardian-case-{}-{}.zip", input.case_id, input.profile);
    crate::commands::export_util::save_bytes_with_dialog(
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
        .filter(|value| matches!(*value, "redacted" | "regression" | "full"))
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
