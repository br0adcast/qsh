//! How a client gets to a qsh daemon: the address ladder (qsh directly, then
//! SSH to bring the daemon up, then qsh again), as a state machine with no
//! I/O. Shared by every client -- the console now, the app later -- so it
//! knows nothing about a terminal: no command line, no exit codes, no text
//! for a person. The caller runs each step and reports how it went.
//! `reconnect` decides when a session whose link died is tried again, and
//! from where.

pub mod ladder;
pub mod reconnect;
pub mod recovery_gate;
pub mod recovery_sweep;
pub mod server_identity;

pub use ladder::*;
