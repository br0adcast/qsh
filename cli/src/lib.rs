//! The `qsh` console client: a terminal over the qsh transport.
//!
//! This is a library crate so every module stays reachable (and therefore
//! warning-free under clippy) as it lands, even before `main` wires it up.

pub mod args;
pub mod background;
mod busy_daemon;
pub mod client_install;
pub mod climb;
pub mod connect;
pub mod escape;
pub mod identity;
mod identity_sequences;
pub mod input_ingress;
#[doc(hidden)]
pub mod input_reader;
#[doc(hidden)]
pub mod input_wake;
mod install_ui;
pub mod keys;
pub mod knock_spec;
pub mod known_hosts;
pub mod log;
pub mod mouse;
pub mod overlay;
pub mod paths;
pub mod port_probe;
pub mod prompt;
pub mod recovery;
pub mod recovery_status;
pub mod releases;
pub mod report;
pub mod road_catalog;
pub mod server_discovery;
pub mod session;
pub mod sessions;
mod sessions_store;
mod signal_wake;
pub mod signals;
pub mod ssh_step;
pub mod status;
pub mod statusline;
pub mod ticker;
pub mod trust;
pub mod tty;
#[doc(hidden)]
pub mod ui_wait;
pub mod upgrade_offer;
pub mod viewport;
pub mod window;

#[cfg(test)]
extern crate self as qsh;

#[cfg(all(test, target_os = "linux"))]
#[path = "main.rs"]
mod cli_entry;

#[cfg(all(test, target_os = "linux"))]
#[test]
fn approved_client_update_dispatches_detach_without_close_session() {
    let events = cli_entry::tests::update_exit_custody_check();
    assert_eq!(
        *events.teardowns.lock().unwrap(),
        vec![connect::Teardown::Detach]
    );
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn refused_shell_discovery_dispatches_detach_without_close_session() {
    let events = cli_entry::tests::refused_shell_discovery_custody_check();
    assert_eq!(
        *events.teardowns.lock().unwrap(),
        vec![connect::Teardown::Detach]
    );
}

#[cfg(all(test, target_os = "linux"))]
mod install_fixture_tests;
