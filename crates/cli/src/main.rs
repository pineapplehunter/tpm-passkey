use clap::{Parser, Subcommand};
use color_eyre::{
    Result,
    eyre::{WrapErr, bail, eyre},
};
use rpassword::prompt_password;
use std::io::{self, Write};
use tabled::{builder::Builder, settings::Style};
use tpm_passkey_protocol as management;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Manage the Linux TPM-backed FIDO2/WebAuthn authenticator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Debug, Subcommand)]
enum Command {
    /// Create the migration key and choose the initial PCR policy
    Setup,
    /// List credentials
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show nonsecret metadata for a local credential ID
    Info {
        id: u64,
        #[arg(long)]
        json: bool,
    },
    /// Migrate every eligible PCR-bound credential
    Migrate {
        #[arg(long)]
        yes: bool,
    },
    /// Show or change daemon configuration
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommand>,
    },
}
#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Show,
    Passphrase,
    Policy {
        #[arg(value_name="PCR", num_args=0..)]
        pcrs: Vec<u32>,
        #[arg(long, conflicts_with = "pcrs")]
        disable: bool,
        #[arg(long)]
        yes: bool,
    },
}
fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().command {
        Command::Setup => setup(),
        Command::List { json } => list(json),
        Command::Info { id, json } => info(id, json),
        Command::Migrate { yes } => migrate(yes),
        Command::Config { command } => match command {
            None | Some(ConfigCommand::Show) => config_show(),
            Some(ConfigCommand::Passphrase) => passphrase(),
            Some(ConfigCommand::Policy { pcrs, disable, yes }) => policy(pcrs, disable, yes),
        },
    }
}
fn request(req: &management::ManagementRequest) -> Result<ciborium::value::Value> {
    let response = management::send_request(req)?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    response
        .result
        .ok_or_else(|| eyre!("daemon returned no result"))
}
fn setup() -> Result<()> {
    let status = request(&management::ManagementRequest::ShowConfig)?;
    if management::value_get(&status, "migration_configured").and_then(|v| v.as_bool())
        == Some(true)
    {
        bail!("setup is already complete; use config policy or config passphrase");
    }
    println!(
        "Choose PCR binding for newly enrolled credentials (e.g. 1 7; empty disables PCR binding). This does not disable migration authorization."
    );
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let pcrs = if line.trim().is_empty() {
        None
    } else {
        let values = parse_pcrs(&line)?;
        validate_pcr_indices(&values)?;
        Some(values)
    };
    warn_about_passphrase();
    let passphrase = prompt_password_confirm("Create migration passphrase: ")?;
    request(&management::ManagementRequest::SetupMigration {
        passphrase,
        pcr_indices: pcrs,
    })?;
    println!("Migration setup complete.");
    Ok(())
}
fn list(json: bool) -> Result<()> {
    let result = request(&management::ManagementRequest::ListCredentials)?;
    let creds = management::value_get(&result, "credentials")
        .and_then(|v| v.as_array())
        .ok_or_else(|| eyre!("invalid credential list from daemon"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&to_json(creds)?)?);
        return Ok(());
    }
    let rows: Vec<Vec<String>> = creds
        .iter()
        .map(|c| {
            vec![
                field(c, "local_id"),
                safe(field(c, "rp_id")),
                safe(account(c)),
                safe(field(c, "registered_at").chars().take(10).collect()),
            ]
        })
        .collect();
    table(&["ID", "SITE", "ACCOUNT", "CREATED"], &rows);
    Ok(())
}
fn info(id: u64, json: bool) -> Result<()> {
    let result = request(&management::ManagementRequest::CredentialInfo { local_id: id })?;
    let names = [
        "local_id",
        "credential_id",
        "rp_id",
        "user_handle",
        "user_name",
        "user_display_name",
        "discoverable",
        "signature_count",
        "created_at",
        "last_used_at",
        "credential_public_key_x",
        "credential_public_key_y",
        "pcr_policy",
        "pcr_indices",
        "pcr_digest",
        "pcr_policy_ref",
        "pcr_authority_name",
        "pcr_authority_signature",
        "pcr_policy_version",
        "migration_configured",
        "migration_label",
        "migration_last_used_at",
        "migration_use_count",
        "migration_public_key_x",
        "migration_public_key_y",
    ];
    if json {
        let pairs = names
            .iter()
            .filter_map(|name| {
                management::value_get(&result, name)
                    .map(|value| ((*name).to_owned(), value_json(value)))
            })
            .collect::<serde_json::Map<_, _>>();
        println!("{}", serde_json::to_string_pretty(&pairs)?);
    } else {
        let rows = names
            .iter()
            .map(|name| {
                vec![
                    (*name).into(),
                    safe(
                        management::value_get(&result, name)
                            .map(value_string)
                            .unwrap_or_else(|| "none".into()),
                    ),
                ]
            })
            .collect::<Vec<_>>();
        table(&["FIELD", "VALUE"], &rows);
    }
    Ok(())
}
fn migrate(yes: bool) -> Result<()> {
    let count = credential_count(true)?;
    if count == 0 {
        println!("No PCR-bound credentials need migration.");
        return Ok(());
    }
    confirm_operation(
        &format!(
            "Migrate all PCR-bound credentials ({count} currently enrolled) to the current boot measurements? Only proceed if you trust this boot state."
        ),
        yes,
    )?;
    let passphrase = read_nonempty_secret("Migration passphrase: ")?;
    let result = request(&management::ManagementRequest::MigrateCredentials {
        passphrase,
        pcr_indices: None,
        credential_ids: Vec::new(),
        all_credentials: true,
        default_policy_change: management::DefaultPcrPolicyChange::Keep,
    })?;
    let (summary, _) = print_results(&result, result_count(&result));
    if summary.succeeded + summary.skipped + summary.failed == 0 {
        println!("No PCR-bound credentials need migration.");
        return Ok(());
    }
    if summary.failed != 0 {
        bail!("one or more credentials could not be migrated");
    }
    Ok(())
}
fn config_show() -> Result<()> {
    let r = request(&management::ManagementRequest::ShowConfig)?;
    let rows = [
        vec![
            "migration_configured".into(),
            value_string(
                management::value_get(&r, "migration_configured")
                    .unwrap_or(&ciborium::value::Value::Null),
            ),
        ],
        vec![
            "default_pcr_policy".into(),
            management::value_get(&r, "default_pcr_policy")
                .map(value_string)
                .unwrap_or_else(|| "none".into()),
        ],
    ];
    table(&["SETTING", "VALUE"], &rows);
    Ok(())
}
fn passphrase() -> Result<()> {
    let old = read_nonempty_secret("Current migration passphrase: ")?;
    warn_about_passphrase();
    let new = prompt_password_confirm("New migration passphrase: ")?;
    request(&management::ManagementRequest::UpdateMigrationPassphrase {
        old_passphrase: Some(old),
        new_passphrase: new,
    })?;
    println!("Migration passphrase updated.");
    Ok(())
}
fn policy(pcrs: Vec<u32>, disable: bool, yes: bool) -> Result<()> {
    if !disable && pcrs.is_empty() {
        let status = request(&management::ManagementRequest::ShowConfig)?;
        table(
            &["SETTING", "VALUE"],
            &[vec![
                "default_pcr_policy".into(),
                field(&status, "default_pcr_policy"),
            ]],
        );
        return Ok(());
    }
    if !disable {
        validate_pcr_indices(&pcrs)?;
    } else if !pcrs.is_empty() {
        bail!("--disable cannot be combined with PCR indices");
    }
    let count = credential_count(false)?;
    let selection = if disable {
        "disabled".into()
    } else {
        pcrs.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    confirm_operation(
        &format!(
            "Set PCR policy to {selection} for all credentials ({count} currently enrolled) and future registrations? Individual updates may fail; successes remain, and the default changes only if all updates succeed."
        ),
        yes,
    )?;
    let passphrase = read_nonempty_secret("Migration passphrase: ")?;
    let default_policy_change = if disable {
        management::DefaultPcrPolicyChange::Disable
    } else {
        management::DefaultPcrPolicyChange::Set {
            pcr_indices: pcrs.clone(),
        }
    };
    let result = request(&management::ManagementRequest::UpdatePcrPolicy {
        passphrase,
        pcr_indices: if disable { Vec::new() } else { pcrs },
        credential_target: management::CredentialTarget::All { all: true },
        default_policy_change,
    })?;
    let (summary, _) = print_results(&result, result_count(&result));
    let default_updated = management::value_get(&result, "default_updated")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !default_updated {
        bail!("not all existing credentials were updated; default policy was not changed");
    }
    if summary.succeeded + summary.skipped + summary.failed == 0 {
        println!("No credentials found; default policy updated.");
    } else {
        println!("Default policy and all existing credential policies updated.");
    }
    Ok(())
}
#[derive(Default)]
struct UpdateSummary {
    succeeded: usize,
    skipped: usize,
    failed: usize,
}

fn result_count(result: &ciborium::value::Value) -> usize {
    management::value_get(result, "results")
        .and_then(|value| value.as_array())
        .map_or(0, Vec::len)
}

fn print_results(result: &ciborium::value::Value, attempted: usize) -> (UpdateSummary, bool) {
    let Some(results) = management::value_get(result, "results").and_then(|v| v.as_array()) else {
        return (
            UpdateSummary {
                failed: attempted,
                ..UpdateSummary::default()
            },
            false,
        );
    };
    let rows = results
        .iter()
        .map(|row| {
            vec![
                safe(field(row, "credential")),
                safe(field(row, "status")),
                safe(if field(row, "reason").is_empty() {
                    field(row, "error")
                } else {
                    field(row, "reason")
                }),
            ]
        })
        .collect::<Vec<_>>();
    table(&["CREDENTIAL", "STATUS", "DETAIL"], &rows);
    let succeeded = results
        .iter()
        .filter(|row| field(row, "status") == "ok")
        .count();
    let skipped = results
        .iter()
        .filter(|row| field(row, "status") == "skipped")
        .count();
    let failed =
        results.len().saturating_sub(succeeded + skipped) + attempted.saturating_sub(results.len());
    (
        UpdateSummary {
            succeeded,
            skipped,
            failed,
        },
        batch_succeeded(result, attempted),
    )
}

fn batch_succeeded(result: &ciborium::value::Value, attempted: usize) -> bool {
    management::value_get(result, "results")
        .and_then(|value| value.as_array())
        .is_some_and(|results| {
            results.len() == attempted && results.iter().all(|row| field(row, "status") == "ok")
        })
}

fn field(v: &ciborium::value::Value, k: &str) -> String {
    management::value_get(v, k)
        .map(value_string)
        .unwrap_or_default()
}
fn value_string(v: &ciborium::value::Value) -> String {
    match v {
        ciborium::value::Value::Text(s) => s.clone(),
        ciborium::value::Value::Null => "none".into(),
        ciborium::value::Value::Bool(b) => b.to_string(),
        ciborium::value::Value::Integer(n) => i64::try_from(*n)
            .map(|number| number.to_string())
            .or_else(|_| u64::try_from(*n).map(|number| number.to_string()))
            .unwrap_or_else(|_| "<integer out of range>".into()),
        ciborium::value::Value::Array(a) => {
            a.iter().map(value_string).collect::<Vec<_>>().join(",")
        }
        _ => format!("{v:?}"),
    }
}
fn value_json(v: &ciborium::value::Value) -> serde_json::Value {
    match v {
        ciborium::value::Value::Text(s) => s.clone().into(),
        ciborium::value::Value::Null => serde_json::Value::Null,
        ciborium::value::Value::Bool(b) => (*b).into(),
        ciborium::value::Value::Integer(n) => u64::try_from(*n)
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
        ciborium::value::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(value_json).collect())
        }
        _ => value_string(v).into(),
    }
}
fn to_json(a: &[ciborium::value::Value]) -> Result<serde_json::Value> {
    Ok(serde_json::Value::Array(
        a.iter()
            .map(|v| {
                let mut m = serde_json::Map::new();
                for k in ["local_id", "rp_id"] {
                    if let Some(value) = management::value_get(v, k) {
                        m.insert(k.into(), value_json(value));
                    }
                }
                m.insert("account".into(), account(v).into());
                m.insert(
                    "created_at".into(),
                    management::value_get(v, "registered_at")
                        .map(value_json)
                        .unwrap_or(serde_json::Value::Null),
                );
                serde_json::Value::Object(m)
            })
            .collect(),
    ))
}
fn account(value: &ciborium::value::Value) -> String {
    let name = field(value, "user_name");
    if name.is_empty() {
        field(value, "user_display_name")
    } else {
        name
    }
}

fn credential_count(pcr_only: bool) -> Result<usize> {
    let result = request(&management::ManagementRequest::ListCredentials)?;
    let credentials = management::value_get(&result, "credentials")
        .and_then(|value| value.as_array())
        .ok_or_else(|| eyre!("invalid credential list from daemon"))?;
    Ok(credentials
        .iter()
        .filter(|credential| {
            !pcr_only
                || management::value_get(credential, "pcr_indices")
                    .and_then(|value| value.as_array())
                    .is_some_and(|indices| !indices.is_empty())
        })
        .count())
}

fn confirm_operation(description: &str, yes: bool) -> Result<()> {
    println!("{description}");
    if yes {
        return Ok(());
    }
    print!("Proceed? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("operation cancelled");
    }
    Ok(())
}

fn warn_about_passphrase() {
    println!(
        "Keep this migration passphrase safe. If you forget it, existing credentials cannot be migrated or have their PCR policy changed. There is no bypass: resetting deletes credentials and requires re-registering them with each site. Signing can continue while the current policy is satisfied."
    );
}

fn safe(s: String) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    for c in s.chars() {
        if c.is_control()
            || (c.is_whitespace() && c != ' ')
            || unicode_general_category::get_general_category(c)
                == unicode_general_category::GeneralCategory::Format
        {
            let _ = write!(o, "\\u{{{:x}}}", c as u32);
        } else {
            o.push(c)
        }
    }
    o
}
fn table(headers: &[&str], rows: &[Vec<String>]) {
    let mut builder = Builder::default();
    builder.push_record(headers.iter().copied());
    for row in rows {
        builder.push_record(row.iter().map(String::as_str));
    }
    println!("{}", builder.build().with(Style::sharp()));
}
fn parse_pcrs(s: &str) -> Result<Vec<u32>> {
    s.split_whitespace()
        .map(|x| x.parse().wrap_err("PCR indices must be integers"))
        .collect()
}
fn validate_pcr_indices(a: &[u32]) -> Result<()> {
    if a.is_empty() || a.iter().any(|&x| x > 23) {
        bail!("PCR indices must be in 0..=23 and selection must not be empty");
    }
    if a.iter()
        .enumerate()
        .any(|(i, index)| a[..i].contains(index))
    {
        bail!("PCR indices must not be repeated");
    }
    Ok(())
}
fn read_secret(p: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        prompt_password(p).wrap_err("reading passphrase")?,
    ))
}
fn read_nonempty_secret(p: &str) -> Result<Zeroizing<String>> {
    let s = read_secret(p)?;
    if s.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(s)
}
fn prompt_password_confirm(p: &str) -> Result<Zeroizing<String>> {
    let s = read_nonempty_secret(p)?;
    let confirm = read_secret("Confirm passphrase: ")?;
    if *s != *confirm {
        bail!("passphrases do not match");
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::cbor;

    #[test]
    fn command_tree_accepts_expected_forms() {
        assert!(Cli::try_parse_from(["tpm-passkey", "setup"]).is_ok());
        assert!(Cli::try_parse_from(["tpm-passkey", "list", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["tpm-passkey", "info", "17", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["tpm-passkey", "migrate", "--yes"]).is_ok());
        assert!(Cli::try_parse_from(["tpm-passkey", "config"]).is_ok());
        assert!(
            Cli::try_parse_from(["tpm-passkey", "config", "policy", "1", "7", "--yes"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["tpm-passkey", "config", "policy", "--disable", "--yes"]).is_ok()
        );
    }

    #[test]
    fn policy_and_json_metadata_are_validated_without_losing_types() {
        assert!(validate_pcr_indices(&[]).is_err());
        assert!(validate_pcr_indices(&[7, 7]).is_err());
        assert!(validate_pcr_indices(&[24]).is_err());
        assert!(validate_pcr_indices(&[1, 7]).is_ok());
        assert!(
            Cli::try_parse_from(["tpm-passkey", "config", "policy", "7", "--disable"]).is_err()
        );
        assert!(Cli::try_parse_from(["tpm-passkey", "info", "not-an-id"]).is_err());
        let metadata = cbor!({"local_id" => 17, "rp_id" => "site", "discoverable" => true,
            "last_used_at" => ciborium::value::Value::Null, "pcr_indices" => [1, 7],
            "encrypted_auth" => "must never be exposed"})
        .unwrap();
        let json = to_json(&[metadata]).unwrap();
        assert_eq!(json[0]["local_id"], 17);
        assert!(json[0]["created_at"].is_null());
        assert_eq!(json[0].as_object().unwrap().len(), 4);
        assert!(json[0].get("discoverable").is_none());
        assert!(json[0].get("encrypted_auth").is_none());
    }

    #[test]
    fn terminal_escape_prevents_controls_and_formats() {
        let escaped = safe("name\t\u{1b}]52;c;bad\u{7}\u{202e}".into());
        assert_eq!(escaped, "name\\u{9}\\u{1b}]52;c;bad\\u{7}\\u{202e}");
    }

    #[test]
    fn only_complete_success_batches_authorize_default_policy_change() {
        let all_ok = cbor!({"results" => [
            {"status" => "ok"}, {"status" => "ok"}
        ]})
        .unwrap();
        let partial = cbor!({"results" => [
            {"status" => "ok"}, {"status" => "error"}
        ]})
        .unwrap();
        assert!(batch_succeeded(&all_ok, 2));
        assert!(!batch_succeeded(&all_ok, 1));
        assert!(!batch_succeeded(&partial, 2));
        assert!(!batch_succeeded(&ciborium::value::Value::Null, 0));
    }
}
