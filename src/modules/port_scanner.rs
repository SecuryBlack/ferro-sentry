use crate::engine::{EventEngine, SecurityEvent, Severity};
use anyhow::Result;
use serde_json::json;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

/// Información de un puerto detectado
#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub local_addr: String,
    pub state: String,
    pub pid: Option<u32>,
    pub service_name: Option<String>,
}

/// Mapeo de puertos well-known a nombres de servicio
fn well_known_service(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        143 => Some("imap"),
        443 => Some("https"),
        445 => Some("smb"),
        1433 => Some("mssql"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        6379 => Some("redis"),
        27017 => Some("mongodb"),
        9200 | 9300 => Some("elasticsearch"),
        _ => None,
    }
}

/// Servicios que tipicamente no deberían estar expuestos públicamente
fn is_sensitive_service(port: u16) -> bool {
    matches!(
        port,
        // Linux/Unix
        22 | 23 | 25 | 53 | 110 | 143 | 3306 | 3389 | 5432 | 6379 | 27017 | 9200 | 9300 |
        // Windows
        135 | 139 | 445 | 5985 | 5986 |
        // Otros críticos
        111 | 2049 | 8080 | 8443
    )
}

/// Servicios que suelen correr sin autenticación por defecto
fn often_unauthenticated(port: u16) -> bool {
    matches!(port, 6379 | 27017 | 9200 | 9300)
}

// ═══════════════════════════════════════════════════════════
// PLATAFORMA: Linux
// ═══════════════════════════════════════════════════════════
#[cfg(target_os = "linux")]
fn get_listening_ports() -> Result<Vec<PortInfo>> {
    let mut results = Vec::new();

    for path in &["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"] {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        let contents = std::fs::read_to_string(path)?;
        let proto = if path.contains("tcp") { "tcp" } else { "udp" };

        for line in contents.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let local = parts[1];
            let state_hex = parts[3];

            // Estado 0A = LISTEN (TCP), 07 = CLOSE_WAIT, etc.
            // Para UDP no hay estado "LISTEN" como tal, pero 07 = CLOSE en /proc/net/udp
            let is_listening = if proto == "tcp" {
                state_hex == "0A"
            } else {
                true // UDP: consideramos todos los locales como "en escucha"
            };

            if !is_listening {
                continue;
            }

            let Some((ip_hex, port_hex)) = local.split_once(':') else {
                continue;
            };

            let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };

            let local_addr = parse_linux_proc_address(ip_hex, port);
            let pid = parts.get(9).and_then(|p| p.parse::<u32>().ok());

            results.push(PortInfo {
                port,
                protocol: proto.to_string(),
                local_addr,
                state: if proto == "tcp" { "LISTEN".to_string() } else { "OPEN".to_string() },
                pid,
                service_name: well_known_service(port).map(|s| s.to_string()),
            });
        }
    }

    Ok(results)
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_address(ip_hex: &str, port: u16) -> String {
    if ip_hex.len() == 8 {
        // IPv4 en hex little-endian: 0100007F -> 127.0.0.1
        let Ok(bytes) = u32::from_str_radix(ip_hex, 16) else {
            return format!("unknown:{}", port);
        };
        let ip = Ipv4Addr::from(bytes.to_le());
        format!("{}:{}", ip, port)
    } else {
        // IPv6: lo dejamos como hex crudo por simplicidad o parseamos
        format!("[{}]:{}", ip_hex, port)
    }
}

// ═══════════════════════════════════════════════════════════
// PLATAFORMA: Windows
// ═══════════════════════════════════════════════════════════
#[cfg(target_os = "windows")]
fn get_listening_ports() -> Result<Vec<PortInfo>> {
    let output = std::process::Command::new("cmd")
        .args(["/c", "netstat", "-ano"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("TCP") && !trimmed.starts_with("UDP") {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        tracing::debug!(line = %trimmed, parts = ?parts, "Parsing netstat line");
        if parts.len() < 4 {
            continue;
        }

        let proto = parts[0].to_lowercase();
        let local = parts[1];
        let state = parts.get(3).unwrap_or(&"UNKNOWN");
        // netstat -ano columns: Proto LocalAddress ForeignAddress [State] PID
        // TCP has State -> PID is at index 4
        // UDP has no State -> PID is at index 3
        let pid_idx = if proto == "udp" { 3 } else { 4 };
        let pid = parts.get(pid_idx).and_then(|p| p.parse::<u32>().ok());

        // Solo LISTENING para TCP
        if proto == "tcp" && *state != "LISTENING" {
            continue;
        }

        let (addr_str, port_str) = match local.rsplit_once(':') {
            Some((a, p)) => (a, p),
            None => continue,
        };

        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };

        results.push(PortInfo {
            port,
            protocol: proto,
            local_addr: format!("{}:{}", addr_str, port),
            state: state.to_string(),
            pid,
            service_name: well_known_service(port).map(|s| s.to_string()),
        });
    }

    Ok(results)
}

// ═══════════════════════════════════════════════════════════
// PLATAFORMA: Fallback / macOS
// ═══════════════════════════════════════════════════════════
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn get_listening_ports() -> Result<Vec<PortInfo>> {
    // Fallback: scan de puertos well-known en localhost
    Ok(scan_well_known_ports("127.0.0.1"))
}

// ═══════════════════════════════════════════════════════════
// Scan de puertos well-known (connect scan) — cross-platform
// ═══════════════════════════════════════════════════════════
fn scan_well_known_ports(target: &str) -> Vec<PortInfo> {
    let ports_to_scan = [
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 27017,
        9200, 9300,
    ];
    let mut results = Vec::new();

    for port in ports_to_scan {
        let addr = SocketAddr::from(SocketAddrV4::new(
            target.parse().unwrap_or(Ipv4Addr::LOCALHOST),
            port,
        ));
        if TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok() {
            results.push(PortInfo {
                port,
                protocol: "tcp".to_string(),
                local_addr: format!("{}:{}", target, port),
                state: "OPEN".to_string(),
                pid: None,
                service_name: well_known_service(port).map(|s| s.to_string()),
            });
        }
    }

    results
}

// ═══════════════════════════════════════════════════════════
// Generación de findings
// ═══════════════════════════════════════════════════════════
pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    let mut events = Vec::new();
    let mut seen_signatures = HashSet::new();

    // 1. Obtener sockets del SO
    let system_ports = get_listening_ports()?;

    for port in &system_ports {
        let is_public = port.local_addr.starts_with("0.0.0.0") || port.local_addr.starts_with("[::]");
        let is_localhost = port.local_addr.starts_with("127.0.0.1") || port.local_addr.starts_with("[::1]");

        // Finding: servicio expuesto públicamente que es sensible
        if is_public && is_sensitive_service(port.port) {
            let sig = format!("exposed_sensitive:{}", port.port);
            if seen_signatures.insert(sig.clone()) {
                let event = engine
                    .build_event(
                        "finding",
                        "posture",
                        Severity::High,
                        "port_scanner",
                        json!({
                            "port": port.port,
                            "protocol": port.protocol,
                            "local_address": port.local_addr,
                            "service": port.service_name.as_deref().unwrap_or("unknown"),
                            "pid": port.pid,
                            "exposure": "public",
                            "recommendation": format!(
                                "Bind {} to 127.0.0.1 o restrinja el acceso con firewall",
                                port.service_name.as_deref().unwrap_or("service")
                            )
                        }),
                        Some(&sig),
                    )
                    .await;
                events.push(event);
            }
        }

        // Finding: servicio sin autenticación expuesto públicamente
        if is_public && often_unauthenticated(port.port) {
            let sig = format!("unauth_exposed:{}", port.port);
            if seen_signatures.insert(sig.clone()) {
                let event = engine
                    .build_event(
                        "finding",
                        "posture",
                        Severity::Critical,
                        "port_scanner",
                        json!({
                            "port": port.port,
                            "protocol": port.protocol,
                            "local_address": port.local_addr,
                            "service": port.service_name.as_deref().unwrap_or("unknown"),
                            "pid": port.pid,
                            "exposure": "public",
                            "risk": "Service typically runs without authentication",
                            "recommendation": "Enable authentication or bind to localhost immediately"
                        }),
                        Some(&sig),
                    )
                    .await;
                events.push(event);
            }
        }

        // Finding: Telnet o FTP activos (protocolos inseguros)
        if matches!(port.port, 21 | 23) && (is_public || is_localhost) {
            let sig = format!("legacy_protocol:{}", port.port);
            if seen_signatures.insert(sig.clone()) {
                let event = engine
                    .build_event(
                        "finding",
                        "posture",
                        Severity::High,
                        "port_scanner",
                        json!({
                            "port": port.port,
                            "protocol": port.protocol,
                            "local_address": port.local_addr,
                            "service": port.service_name.as_deref().unwrap_or("unknown"),
                            "pid": port.pid,
                            "risk": "Unencrypted legacy protocol detected",
                            "recommendation": "Replace with SFTP/SSH"
                        }),
                        Some(&sig),
                    )
                    .await;
                events.push(event);
            }
        }
    }

    // 2. Scan de puertos well-known en localhost como doble check (solo si no hay datos del SO)
    if system_ports.is_empty() {
        let scanned = scan_well_known_ports("127.0.0.1");
        for port in scanned {
            let sig = format!("well_known_open:{}", port.port);
            if seen_signatures.insert(sig.clone()) {
                let event = engine
                    .build_event(
                        "finding",
                        "posture",
                        Severity::Medium,
                        "port_scanner",
                        json!({
                            "port": port.port,
                            "protocol": port.protocol,
                            "local_address": port.local_addr,
                            "service": port.service_name.as_deref().unwrap_or("unknown"),
                            "source": "connect_scan",
                            "recommendation": "Review if this service should be running"
                        }),
                        Some(&sig),
                    )
                    .await;
                events.push(event);
            }
        }
    }

    Ok(events)
}
