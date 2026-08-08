//! `buzz moderation` — community moderation queue, enforcement, and audit.
//!
//! Mutations (`ban`/`unban`/`timeout`/`untimeout`/`resolve`) are signed
//! command events (kinds 9040–9044) submitted via `POST /events`, mirroring
//! the NIP-43 relay-admin 9030-series: the relay validates, authorizes
//! (owner/admin only), and executes them directly — they are never stored.
//!
//! Reads (`reports`/`restricted`/`audit`) hit dedicated mod-only,
//! NIP-98-authed relay endpoints under `/moderation/*`, because reports and
//! audit rows are structured queue rows, not public nostr events — serving
//! them over a REQ filter would mean synthesizing fake events and threading a
//! privileged authz check into the public read path.
//!
//! The community (tenant) is selected by the relay host — moderation commands
//! carry no channel scope.

use nostr::Timestamp;

use crate::client::{normalize_write_response, BuzzClient};
use crate::error::CliError;
use crate::validate::validate_hex64;
use crate::{ModerationCmd, OutputFormat};

use super::parse_json_array_response;

fn normalize_moderation_rows(raw: &str, operation: &str) -> Result<String, CliError> {
    let rows = parse_json_array_response(raw, operation)?;
    serde_json::to_string(&rows)
        .map_err(|error| CliError::Other(format!("failed to serialize {operation}: {error}")))
}

/// Resolve `--expires-in <secs>` / `--expires-at <unix>` into an absolute
/// unix-seconds expiry. At most one may be set (enforced by clap).
fn resolve_expiry(
    expires_in: Option<u64>,
    expires_at: Option<u64>,
) -> Result<Option<u64>, CliError> {
    match (expires_in, expires_at) {
        (Some(secs), _) => Timestamp::now()
            .as_secs()
            .checked_add(secs)
            .map(Some)
            .ok_or_else(|| CliError::Usage("--expires-in produces an invalid timestamp".into())),
        (None, Some(ts)) => Ok(Some(ts)),
        (None, None) => Ok(None),
    }
}

async fn cmd_ban(
    client: &BuzzClient,
    pubkey: &str,
    expires_in: Option<u64>,
    expires_at: Option<u64>,
    reason: Option<&str>,
) -> Result<(), CliError> {
    validate_hex64(pubkey)?;
    let expiry = resolve_expiry(expires_in, expires_at)?;
    let builder = buzz_sdk::build_moderation_ban(pubkey, expiry, reason)
        .map_err(|e| CliError::Usage(format!("invalid ban: {e}")))?;
    let event = client.sign_event(builder)?;
    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

async fn cmd_unban(client: &BuzzClient, pubkey: &str) -> Result<(), CliError> {
    validate_hex64(pubkey)?;
    let builder = buzz_sdk::build_moderation_unban(pubkey)
        .map_err(|e| CliError::Usage(format!("invalid unban: {e}")))?;
    let event = client.sign_event(builder)?;
    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

async fn cmd_timeout(
    client: &BuzzClient,
    pubkey: &str,
    expires_in: Option<u64>,
    expires_at: Option<u64>,
    reason: Option<&str>,
) -> Result<(), CliError> {
    validate_hex64(pubkey)?;
    let expiry = resolve_expiry(expires_in, expires_at)?
        .ok_or_else(|| CliError::Usage("timeout requires --expires-in or --expires-at".into()))?;
    let builder = buzz_sdk::build_moderation_timeout(pubkey, expiry, reason)
        .map_err(|e| CliError::Usage(format!("invalid timeout: {e}")))?;
    let event = client.sign_event(builder)?;
    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

async fn cmd_untimeout(client: &BuzzClient, pubkey: &str) -> Result<(), CliError> {
    validate_hex64(pubkey)?;
    let builder = buzz_sdk::build_moderation_untimeout(pubkey)
        .map_err(|e| CliError::Usage(format!("invalid untimeout: {e}")))?;
    let event = client.sign_event(builder)?;
    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

async fn cmd_resolve(
    client: &BuzzClient,
    report: &str,
    status: &str,
    action: &str,
    reason: Option<&str>,
) -> Result<(), CliError> {
    validate_hex64(report)?;
    let builder = buzz_sdk::build_moderation_resolve_report(report, status, action, reason)
        .map_err(|e| CliError::Usage(format!("invalid resolution: {e}")))?;
    let event = client.sign_event(builder)?;
    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

async fn cmd_reports(
    client: &BuzzClient,
    status: Option<&str>,
    limit: u32,
) -> Result<(), CliError> {
    let mut path = format!("/moderation/reports?limit={limit}");
    if let Some(s) = status {
        path.push_str(&format!("&status={s}"));
    }
    let resp = client.get_authed(&path).await?;
    println!(
        "{}",
        normalize_moderation_rows(&resp, "moderation reports")?
    );
    Ok(())
}

async fn cmd_restricted(client: &BuzzClient) -> Result<(), CliError> {
    let resp = client.get_authed("/moderation/restricted").await?;
    println!(
        "{}",
        normalize_moderation_rows(&resp, "moderation restrictions")?
    );
    Ok(())
}

async fn cmd_audit(client: &BuzzClient, limit: u32) -> Result<(), CliError> {
    let resp = client
        .get_authed(&format!("/moderation/audit?limit={limit}"))
        .await?;
    println!("{}", normalize_moderation_rows(&resp, "moderation audit")?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{normalize_moderation_rows, resolve_expiry};

    #[test]
    fn relative_moderation_expiry_rejects_timestamp_overflow() {
        assert!(resolve_expiry(Some(u64::MAX), None).is_err());
        assert_eq!(resolve_expiry(None, Some(42)).unwrap(), Some(42));
        assert_eq!(resolve_expiry(None, None).unwrap(), None);
    }

    #[test]
    fn moderation_reads_reject_malformed_or_wrong_shaped_success_bodies() {
        assert_eq!(
            normalize_moderation_rows("[]", "moderation audit").unwrap(),
            "[]"
        );
        assert!(normalize_moderation_rows("{}", "moderation audit").is_err());
        assert!(normalize_moderation_rows("not-json", "moderation audit").is_err());
    }
}

pub async fn dispatch(
    cmd: ModerationCmd,
    client: &BuzzClient,
    _format: &OutputFormat,
) -> Result<(), CliError> {
    match cmd {
        ModerationCmd::Reports { status, limit } => {
            cmd_reports(client, status.as_deref(), limit).await
        }
        ModerationCmd::Resolve {
            report,
            status,
            action,
            reason,
        } => cmd_resolve(client, &report, &status, &action, reason.as_deref()).await,
        ModerationCmd::Ban {
            pubkey,
            expires_in,
            expires_at,
            reason,
        } => cmd_ban(client, &pubkey, expires_in, expires_at, reason.as_deref()).await,
        ModerationCmd::Unban { pubkey } => cmd_unban(client, &pubkey).await,
        ModerationCmd::Timeout {
            pubkey,
            expires_in,
            expires_at,
            reason,
        } => cmd_timeout(client, &pubkey, expires_in, expires_at, reason.as_deref()).await,
        ModerationCmd::Untimeout { pubkey } => cmd_untimeout(client, &pubkey).await,
        ModerationCmd::Restricted => cmd_restricted(client).await,
        ModerationCmd::Audit { limit } => cmd_audit(client, limit).await,
    }
}
