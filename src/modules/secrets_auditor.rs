//! SECRETS-001: secretos en claro en el disco.
//!
//! Es lo primero que recoge quien entra con credenciales robadas, y lo que
//! leen los gusanos de npm (`~/.npmrc`, `~/.aws`, claves SSH, `.env`) para
//! propagarse. Solo se informa de la ruta, el tipo y si cualquiera puede
//! leerlo: **el contenido nunca sale del servidor**.

use crate::engine::{EventEngine, SecurityEvent};
use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::engine::Severity;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::path::Path;

/// Ficheros de credenciales dentro de cada directorio personal y la marca
/// que demuestra que llevan un secreto (no basta con que existan).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const HOME_CREDENTIAL_FILES: &[(&str, &str, &str)] = &[
    (".aws/credentials", "aws_secret_access_key", "aws"),
    (".npmrc", "_auth", "npm"),
    (".pypirc", "password", "pypi"),
    (".git-credentials", "@", "git"),
    (".docker/config.json", "\"auth\"", "docker"),
    (".netrc", "password", "netrc"),
    (".config/gh/hosts.yml", "oauth_token", "github_cli"),
    (".kube/config", "token", "kubernetes"),
];

#[cfg(target_os = "linux")]
const ENV_ROOTS: &[&str] = &["/root", "/home", "/opt", "/srv", "/var/www"];
#[cfg(target_os = "linux")]
const ENV_MAX_DEPTH: usize = 4;
#[cfg(target_os = "linux")]
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".cache",
    "target",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".npm",
    ".cargo",
    ".rustup",
    "proc",
];
/// ponytail: tope fijo de entradas recorridas para que un `/opt` enorme no
/// alargue la auditoría; subirlo o hacerlo configurable si se queda corto.
#[cfg(target_os = "linux")]
const MAX_WALK_ENTRIES: usize = 50_000;
#[cfg(target_os = "linux")]
const MAX_REPORTED_FILES: usize = 50;

pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let found = tokio::task::spawn_blocking(find_secrets).await?;

        if found.is_empty() {
            findings.push(
                engine
                    .build_resolved_event("secrets_auditor", "plaintext_secrets")
                    .await,
            );
            return Ok(findings);
        }

        let any_world_readable = found.iter().any(|f| f.world_readable);
        let only_ssh_keys = found.iter().all(|f| f.kind == "ssh_key_unencrypted");
        let severity = if any_world_readable {
            Severity::High
        } else if only_ssh_keys {
            Severity::Low
        } else {
            Severity::Medium
        };

        let total = found.len();
        let files: Vec<_> = found
            .iter()
            .take(MAX_REPORTED_FILES)
            .map(|f| json!({ "path": f.path, "kind": f.kind, "world_readable": f.world_readable }))
            .collect();

        let details = json!({
            "rule_id": "SECRETS-001",
            "title": "Plaintext Secrets On Disk",
            "count": total,
            "truncated": total > MAX_REPORTED_FILES,
            "files": files,
            "summary": format!(
                "{} file(s) with credentials stored in plaintext{}. Anyone who gets in with stolen credentials, or a malicious package, reads these first.",
                total,
                if any_world_readable { ", some readable by any user on the server" } else { "" }
            ),
            "remediation": "Restrict them to their owner (chmod 600), remove the ones you no longer use, add a passphrase to SSH keys, and prefer short-lived tokens or a secret manager. If a file was world-readable, rotate what it contains."
        });

        findings.push(
            engine
                .build_event(
                    "finding",
                    "secrets",
                    severity,
                    "secrets_auditor",
                    details,
                    Some("plaintext_secrets"),
                )
                .await,
        );
    }

    let _ = engine;

    Ok(findings)
}

#[cfg(target_os = "linux")]
struct SecretFile {
    path: String,
    kind: &'static str,
    world_readable: bool,
}

#[cfg(target_os = "linux")]
fn find_secrets() -> Vec<SecretFile> {
    let mut found = Vec::new();

    for home in super::home_dirs() {
        for (rel, marker, kind) in HOME_CREDENTIAL_FILES {
            let path = home.join(rel);
            if read_small(&path).is_some_and(|c| c.contains(marker)) {
                push(&mut found, &path, kind);
            }
        }

        let Ok(entries) = std::fs::read_dir(home.join(".ssh")) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "pub") {
                continue;
            }
            if read_small(&path).is_some_and(|c| private_key_unencrypted(&c) == Some(true)) {
                push(&mut found, &path, "ssh_key_unencrypted");
            }
        }
    }

    // Los `.env` de las apps son normales; el problema es que los lea cualquiera.
    let mut budget = MAX_WALK_ENTRIES;
    for root in ENV_ROOTS {
        walk_env_files(Path::new(root), 0, &mut budget, &mut found);
    }

    found.sort_by(|a, b| a.path.cmp(&b.path));
    found.dedup_by(|a, b| a.path == b.path);
    found
}

#[cfg(target_os = "linux")]
fn walk_env_files(dir: &Path, depth: usize, budget: &mut usize, found: &mut Vec<SecretFile>) {
    if depth > ENV_MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        // symlink_metadata: no seguir enlaces (bucles, salir del árbol).
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if meta.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk_env_files(&entry.path(), depth + 1, budget, found);
            }
        } else if meta.is_file()
            && is_env_file_name(&name)
            && meta.permissions().mode() & 0o004 != 0
        {
            push(found, &entry.path(), "env_file");
        }
    }
}

#[cfg(target_os = "linux")]
fn push(found: &mut Vec<SecretFile>, path: &Path, kind: &'static str) {
    let world_readable = std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o004 != 0)
        .unwrap_or(false);
    found.push(SecretFile {
        path: path.to_string_lossy().to_string(),
        kind,
        world_readable,
    });
}

/// Contenido de un fichero regular de menos de 1 MB; si no, `None`.
#[cfg(target_os = "linux")]
fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// `.env` y `.env.<algo>`, salvo las plantillas que se versionan sin secretos.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_env_file_name(name: &str) -> bool {
    if name == ".env" {
        return true;
    }
    match name.strip_prefix(".env.") {
        Some(suffix) => !matches!(
            suffix,
            "example" | "sample" | "template" | "dist" | "defaults" | "schema"
        ),
        None => false,
    }
}

/// `Some(true)` = clave privada sin passphrase; `Some(false)` = cifrada;
/// `None` = no es una clave privada.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn private_key_unencrypted(content: &str) -> Option<bool> {
    if !content.contains("PRIVATE KEY-----") {
        return None;
    }
    if content.contains("BEGIN OPENSSH PRIVATE KEY") {
        // Cabecera binaria en base64: "openssh-key-v1\0" + cifrado "none".
        let body = content.lines().nth(1)?;
        return Some(body.starts_with("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU"));
    }
    // PEM: "Proc-Type: 4,ENCRYPTED" o "BEGIN ENCRYPTED PRIVATE KEY".
    Some(!content.contains("ENCRYPTED"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecta_claves_ssh_sin_cifrar() {
        let plain = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
        let enc = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNy\n-----END OPENSSH PRIVATE KEY-----\n";
        let pem_enc = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nabc\n-----END RSA PRIVATE KEY-----\n";
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(private_key_unencrypted(plain), Some(true));
        assert_eq!(private_key_unencrypted(enc), Some(false));
        assert_eq!(private_key_unencrypted(pem_enc), Some(false));
        assert_eq!(private_key_unencrypted(pem), Some(true));
        assert_eq!(private_key_unencrypted("ssh-ed25519 AAAA mikel@pc"), None);
    }

    #[test]
    fn nombres_de_env() {
        assert!(is_env_file_name(".env"));
        assert!(is_env_file_name(".env.production"));
        assert!(is_env_file_name(".env.uptime-monitor"));
        assert!(!is_env_file_name(".env.example"));
        assert!(!is_env_file_name(".environment"));
        assert!(!is_env_file_name("env"));
    }
}
