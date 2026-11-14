//! Stable-owner contracts and independently constructed engine.
//! Production daemon routing does not construct or advertise this runtime.
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

pub mod engine;
#[cfg(all(test, target_os = "linux"))]
mod engine_native_tests;
pub mod resources;
#[cfg(test)]
mod resources_tests;

pub mod input;
pub mod recovery_runtime;
mod writer;

#[allow(dead_code)] // Dormant state shard; real proof/custody adapters are not integrated.
pub(crate) mod authorization;
#[allow(dead_code)] // No host process, endpoint, or writer is activated.
pub(crate) mod host;
mod output;
pub mod screen_control;
pub mod screen_owner;
pub mod screen_recovery;

pub mod host_auth_contract;
pub mod local_admission_contract;
#[cfg(test)]
mod local_ipc_contract_tests;
pub mod owner_resource_contract;

#[allow(dead_code)] // Dormant inherited-channel component; no endpoint is activated.
pub(crate) mod local_channel;

#[allow(dead_code)] // Dormant host-issued resource custody; no runtime activated.
pub(crate) mod host_resources;
