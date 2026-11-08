//! Inactive stable-owner IPC contracts. No owner process or retained-session
//! runtime is created by this module.
#[cfg(test)]
mod extension_tests;
pub mod protocol;
#[cfg(test)]
mod protocol_tests;

pub mod authorization_contract;
pub mod host_protocol;
pub mod status_contract;
mod wire;

pub mod operations;
pub mod resource_contract;
