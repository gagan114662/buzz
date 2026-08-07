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
