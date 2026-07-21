# Ferro-Sentry

Agente de seguridad de servidor (EDR + Postura + Visibilidad) escrito en Rust. Corre dentro del servidor, detecta amenazas en tiempo real, audita la postura de seguridad y reporta a SecuryBlack Cloud.

> **Estado:** Diseño y planificación (Roadmap activo).

---

## 🛡️ Filosofía

- **Rust nativo** por rendimiento, footprint mínimo y seguridad memory-safe.
- **Módulos independientes**, cada sensor corre en su propia tarea `tokio`.
- **Dos modos de salida:** a través de **Conduit** (túnel local) o **directo** a la API de SecuryBlack.
- **Alertas en tiempo real** + **auditorías periódicas** programadas.
- **Cross-platform** primero (Linux/Windows), luego macOS.

---

## 📋 Módulos y Funciones

### 🔴 Módulos de Detección en Tiempo Real (EDR)

| Módulo | Qué detecta |
|--------|-------------|
| **Process Sentinel** | Procesos nuevos, hijos de shells, ejecución desde `/tmp` o paths temporales, procesos sin padre, inyección de memoria, binarios borrados en ejecución (`/proc/[pid]/exe` dangling) |
| **File Integrity Monitor (FIM)** | Modificaciones en `/etc/passwd`, binarios del sistema, configs críticas, certificados. Baseline de hashes SHA-256 con snapshot inicial. |
| **Network Watch** | Conexiones outbound sospechosas, reverse shells, beaconing, escaneo interno, conexiones a IPs/tor/proxies conocidos. |
| **Auth Guard** | Logins SSH fallidos, brute force, sudo abuse, nuevos usuarios, cambios de password, logins en horarios atípicos. |
| **Persistence Hunter** | Nuevos cron jobs, servicios systemd, tareas programadas (Windows), registros de startup, `.bashrc`/`.profile` modificados, DLL hijacking (Windows). |
| **Log Watcher** | Tail en tiempo real de logs del sistema (`auth.log`, `journald`, Windows Event Log) con reglas regex/YAML externas. |

### 🔵 Módulos de Auditoría y Postura (CSPM ligero)

| Módulo | Qué audita |
|--------|------------|
| **Port Scanner** | Puertos abiertos en interfaces locales, servicios escuchando en `0.0.0.0` sin necesidad, servicios en puertos no estándar. Escaneo SYN rápido de localhost. |
| **Firewall Auditor** | Reglas de `iptables`/`nftables`/`ufw` (Linux) y Windows Firewall. Detecta reglas permisivas (`ANY/ANY`, `0.0.0.0/0`), reglas sin stateful inspection, denegaciones ausentes. |
| **Vulnerability Scanner** | Versiones de software expuestas vs base de CVEs local (opcional), configs inseguras (SSH root login, TLS 1.0/1.1, SMBv1, etc.), parches de kernel pendientes. |
| **SSL/TLS Auditor** | Certificados expirados, self-signed, configuraciones débiles (cifrados RC4/DES, DH small), certificados próximos a expirar. |
| **SSH Auditor** | Configuración de `sshd`: `PermitRootLogin`, `PasswordAuthentication`, `Port 22`, `X11Forwarding`, `AllowUsers` ausente, versión obsoleta. |
| **Permission Auditor** | Binarios SUID/SGID sospechosos, archivos world-writable en paths críticos, usuarios con UID 0 duplicados, grupos `sudo`/`wheel` no autorizados. |
| **Secrets Hunter** | Credenciales hardcodeadas en archivos de config (`.env`, `.yml`, `.json`), API keys, private keys sin passphrase, tokens en logs. |
| **Kernel Security** | Estado de mitigaciones (`ASLR`, `NX`, `seccomp`, `AppArmor`/`SELinux`, `KPTI`, `SMEP`/`SMAP`), kernel desactualizado. |
| **Listening Services** | Servicios activos sin autenticación, bases de datos expuestas (`MongoDB`, `Redis`, `Elasticsearch` sin auth), servicios legacy (`Telnet`, `FTP`). |
| **Container Security** | Contenedores Docker privilegiados, montajes de `/var/run/docker.sock`, imágenes desactualizadas, containers con `--net=host` innecesario, metadata abuse (`169.254.169.254`). |
| **Backup Finder** | Backups expuestos (`.sql`, `.tar.gz`, `.zip`, `.bak`) en paths web accesibles o con permisos débiles. |
| **Network Topology** | Interfaces en modo promiscuo, rutas estáticas sospechosas, tunnels no autorizados (WireGuard, OpenVPN, GRE), ARP spoofing. |
| **Malware Scanner** | Scan con firmas YARA de directorios críticos (`/tmp`, `/var/tmp`, `$HOME`), IOCs (indicators of compromise) en disco. |

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SECURYBLACK CLOUD                                         │
│  ┌──────────────┐      ┌──────────────────────────────┐                     │
│  │  Dashboard   │◄─────┤  Security Events API         │                     │
│  │  (alertas)   │      │  / Posture API               │                     │
│  └──────────────┘      └──────────────────────────────┘                     │
└─────────────────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Security Events (JSON/OTLP Logs)
                    ┌─────────┴──────────┐
                    │   Conduit (túnel)  │   ← default
                    └─────────┬──────────┘
┌─────────────────────────────┼───────────────────────────────┐
│     SERVIDOR DEL CLIENTE    │                               │
│                             │                               │
│  ┌──────────────────────────┴─────────────────────────┐     │
│  │  Ferro-Sentry (Servicio Rust)                       │     │
│  │                                                    │     │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │     │
│  │  │ REAL-TIME   │  │ AUDIT       │  │ SCHEDULER  │ │     │
│  │  │ SENSORS     │  │ SCANNERS    │  │ (cron)     │ │     │
│  │  │             │  │             │  │            │ │     │
│  │  │ • Process   │  │ • PortScan  │  │ • Daily    │ │     │
│  │  │ • FIM       │  │ • Firewall  │  │ • Hourly   │ │     │
│  │  │ • Network   │  │ • VulnScan  │  │ • OnDemand │ │     │
│  │  │ • Auth      │  │ • SSH       │  │            │ │     │
│  │  │ • Persist   │  │ • Secrets   │  │            │ │     │
│  │  │ • Logs      │  │ • Perms     │  │            │ │     │
│  │  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘ │     │
│  │         └─────────────────┴───────────────┘        │     │
│  │  ┌────────────────────────────────────────────────┐ │     │
│  │  │           EVENT ENGINE                         │ │     │
│  │  │  • Deduplicación (ventana 5min)               │ │     │
│  │  │  • Enriquecimiento (host, user, hash, geo)    │ │     │
│  │  │  • Severity scoring                           │ │     │
│  │  │  • Throttling / rate limiting                 │ │     │
│  │  └────────────────────┬───────────────────────────┘ │     │
│  │  ┌────────────────────┴───────────────────────────┐ │     │
│  │  │           OUTPUT LAYER                         │ │     │
│  │  │  → Conduit local (gRPC/HTTP)    [default]     │ │     │
│  │  │  → Directo a API SB (reqwest)   [fallback]    │ │     │
│  │  │  → Archivo local JSONL          [debug]       │ │     │
│  │  └────────────────────────────────────────────────┘ │     │
│  └─────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Tipos de Eventos

**Security Event** (alerta en tiempo real):
```json
{
  "event_type": "process_spawn",
  "category": "intrusion_detection",
  "severity": "critical",
  "timestamp": "2026-04-28T16:45:00Z",
  "host": "web-server-01",
  "agent": "ferro-sentry",
  "module": "process_sentinel",
  "details": {
    "pid": 1337,
    "command": "/tmp/.xmrig --donate-level 1",
    "parent_pid": 1,
    "parent_command": "systemd",
    "user": "www-data",
    "hash_sha256": "aabbcc...",
    "rule": "process_from_tmp"
  }
}
```

**Posture Finding** (hallazgo de auditoría):
```json
{
  "event_type": "finding",
  "category": "posture",
  "severity": "high",
  "timestamp": "2026-04-28T16:45:00Z",
  "host": "web-server-01",
  "agent": "ferro-sentry",
  "module": "ssh_auditor",
  "details": {
    "finding": "PermitRootLogin=yes",
    "recommendation": "Set PermitRootLogin=no or prohibit-password",
    "file": "/etc/ssh/sshd_config",
    "benchmark": "CIS-5.2.8"
  }
}
```

---

## 🦀 Stack Tecnológico Rust

| Capa | Crate |
|------|-------|
| Async runtime | `tokio` (full) |
| Logging / tracing | `tracing` + `tracing-subscriber` + `tracing-appender` |
| Serialización | `serde` + `serde_json` + `serde_yaml` (reglas) + `chrono` |
| Procesos / sistema | `sysinfo` |
| File system events | `notify` (inotify, fsevents, ReadDirectoryChangesW) |
| Hashes (FIM) | `sha2` + `hex` |
| Regex | `regex` |
| Usuarios del sistema | `uzers` |
| Windows APIs | `windows` + `winreg` |
| HTTP client | `reqwest` |
| gRPC / OTLP Logs | `tonic` + `opentelemetry` + `opentelemetry-otlp` |
| Scanning de red | `tokio::net` + raw sockets (libpcap vía `pnet` opcional) |
| YARA | `yara` / `yara-sys` (opcional) |
| Auto-update | `self_update` |
| Windows service | `windows-service` |
| Config | `toml` + `serde` |

---

## 📁 Estructura del Proyecto

```
ferro-sentry/
├── Cargo.toml
├── rules/                          ← Reglas de detección (YAML)
│   ├── process_rules.yaml
│   ├── network_rules.yaml
│   ├── log_rules.yaml
│   └── audit_profiles.yaml         ← Perfiles de auditoría (CIS lite)
├── src/
│   ├── main.rs                     # Entry point, service wrapper
│   ├── config.rs                   # Config TOML + env vars
│   ├── scheduler.rs                # Programación de scans periódicos
│   ├── engine/
│   │   ├── mod.rs                  # Event Engine central
│   │   ├── dedup.rs                # Deduplicación por firma
│   │   ├── enrich.rs               # Enriquecimiento de eventos
│   │   ├── severity.rs             # Scoring
│   │   └── throttle.rs             # Rate limiting
│   ├── modules/
│   │   ├── mod.rs
│   │   ├── process_sentinel.rs
│   │   ├── file_integrity.rs
│   │   ├── network_watch.rs
│   │   ├── auth_guard.rs
│   │   ├── persistence_hunter.rs
│   │   ├── log_watcher.rs
│   │   ├── port_scanner.rs
│   │   ├── firewall_auditor.rs
│   │   ├── vuln_scanner.rs
│   │   ├── ssl_auditor.rs
│   │   ├── ssh_auditor.rs
│   │   ├── permission_auditor.rs
│   │   ├── secrets_hunter.rs
│   │   ├── kernel_security.rs
│   │   ├── listening_services.rs
│   │   ├── container_security.rs
│   │   ├── backup_finder.rs
│   │   ├── network_topology.rs
│   │   └── malware_scanner.rs
│   ├── output/
│   │   ├── mod.rs                  # Trait Output
│   │   ├── conduit.rs              # Default: vía Conduit
│   │   ├── direct.rs               # Fallback: HTTP directo
│   │   └── local_file.rs           # Debug: JSONL local
│   └── updater/
│       └── mod.rs
├── scripts/
│   ├── install.sh
│   └── install.ps1
└── .github/
    └── workflows/
        └── release.yml
```

---

## 📅 Roadmap

### Fase 0 — Fundación
- [ ] Repo, CI/CD cross-platform, config, logging, output layer.
- [ ] Event Engine (deduplicación, severidad, throttling).
- [ ] Integración con Conduit (default) y fallback directo.

### Fase 1 — Visibilidad Básica (CIS Lite)
- [ ] **Port Scanner** — Escaneo local de puertos abiertos.
- [ ] **Listening Services** — Servicios activos y su exposición.
- [ ] **Firewall Auditor** — Reglas de iptables/nftables/Windows Firewall.
- [ ] **SSL/TLS Auditor** — Certificados expirados/débiles.
- [ ] **SSH Auditor** — Configuración insegura de sshd.
- [ ] **Permission Auditor** — SUID binaries, world-writable files.

### Fase 2 — Detección en Tiempo Real (EDR Core)
- [ ] **File Integrity Monitor (FIM)** — Baseline + watcher en tiempo real.
- [ ] **Process Sentinel** — Procesos nuevos, árboles sospechosos.
- [ ] **Auth Guard** — Logins fallidos, brute force, sudo.
- [ ] **Log Watcher** — Tail de logs con reglas regex.

### Fase 3 — Postura y Hardening
- [ ] **Vulnerability Scanner** — Versiones vs CVEs, parches pendientes.
- [ ] **Secrets Hunter** — API keys, credenciales en config.
- [ ] **Kernel Security** — ASLR, SELinux/AppArmor, seccomp.
- [ ] **Persistence Hunter** — Cron, systemd, startup.
- [ ] **Network Watch** — Conexiones outbound sospechosas.

### Fase 4 — Container, Cloud & Malware
- [ ] **Container Security** — Docker privileged, sockets, metadata abuse.
- [ ] **Backup Finder** — Backups expuestos en paths web.
- [ ] **Network Topology** — Promiscuous mode, tunnels no autorizados.
- [ ] **Malware Scanner** — YARA scanning de directorios críticos.

### Fase 5 — Inteligencia y Respuesta
- [ ] **Anomaly Baseline** — Aprendizaje de comportamiento normal.
- [ ] **Threat Intelligence** — Matching de IoCs (IPs, hashes, dominios).
- [ ] **Respuesta Automática** — Kill process, aislar red, bloquear IP (opt-in).

---

## 🔗 Integración con OxiPulse y Conduit

| Agente | Rol | Protocolo de salida |
|--------|-----|---------------------|
| **OxiPulse** | Monitorización de salud del sistema (CPU, RAM, disco, red) | OTLP Metrics → gRPC (directo o vía Conduit) |
| **Ferro-Sentry** | Seguridad del endpoint (EDR + postura) | Security Events JSON / OTLP Logs → Conduit o directo |
| **Conduit** | Túnel y orquestador de agentes SB | Túnel bidireccional gRPC con SB Cloud |

Ferro-Sentry se registra automáticamente en Conduit si está presente. Si no, usa `reqwest` directo.

---

## ❓ Decisiones Pendientes

1. **Base de CVEs:** ¿Incluimos una base local de CVEs (vulns.json) o consultamos API externa?
2. **YARA:** ¿Incluimos reglas YARA por defecto o es opt-in por tamaño?
3. **Respuesta automática:** ¿Fase 5 o nunca? Es peligroso en producción.
4. **Windows Event Log:** ¿Usamos crate `windows` directo o biblioteca como `winevt`?

---

## License

FerroSentry is licensed under the [Apache License, Version 2.0](LICENSE).


