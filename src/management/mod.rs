//! Comandos que FerroSentry ejecuta cuando llegan por el intake local
//! (`sb_agent_core::command_intake`) — típicamente reenviados por nexus
//! desde el túnel, pero el mismo intake funciona standalone: cualquier
//! llamante local (el propio `ferro-sentry` por CLI, más adelante) puede
//! disparar el mismo handler sin pasar por la nube.
//!
//! Ver `D:\infra\docs\design-command-intake.md` para el porqué: FerroSentry
//! es dueño de la remediación de su propio dominio (postura/EDR), no nexus.

pub mod commands;
