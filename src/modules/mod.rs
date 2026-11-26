pub mod auth_monitor;
pub mod fim;
pub mod firewall_auditor;
pub mod intrusion_prevention_auditor;
pub mod permission_auditor;
pub mod persistence_hunter;
pub mod port_scanner;
pub mod process_sentinel;
pub mod secrets_auditor;
pub mod ssh_auditor;
pub mod ssl_auditor;
pub mod vuln_scanner;

/// Directorios personales de `/etc/passwd` que existen (root incluido),
/// sin repetir y sin los falsos (`/`, `/nonexistent`). Vacío fuera de Linux.
pub fn home_dirs() -> Vec<std::path::PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    parse_homes(&passwd)
        .into_iter()
        .filter(|h| h.is_dir())
        .collect()
}

fn parse_homes(passwd: &str) -> Vec<std::path::PathBuf> {
    let mut homes: Vec<std::path::PathBuf> = Vec::new();
    for line in passwd.lines() {
        let Some(home) = line.split(':').nth(5) else {
            continue;
        };
        if home.is_empty() || home == "/" || home.starts_with("/nonexistent") {
            continue;
        }
        let home = std::path::PathBuf::from(home);
        if !homes.contains(&home) {
            homes.push(home);
        }
    }
    homes
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_homes_salta_falsos_y_repetidos() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                      nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
                      raro:x:2:2::/:/bin/sh\n\
                      mikel:x:1000:1000::/home/mikel:/bin/bash\n\
                      otro:x:1001:1001::/home/mikel:/bin/bash\n";
        let homes = super::parse_homes(passwd);
        assert_eq!(
            homes,
            vec![
                std::path::PathBuf::from("/root"),
                std::path::PathBuf::from("/usr/sbin"),
                std::path::PathBuf::from("/home/mikel"),
            ]
        );
    }
}
