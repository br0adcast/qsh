// qsh modification: caller-provided private-key documentation; see README.qsh.md.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]

//! ## Usage
//!
//! The main types provided by this library are:
//!
//! - [`Certificate`]: OpenSSH certificates
//! - [`Fingerprint`]: public key fingerprints (i.e. hashes)
//! - [`PrivateKey`]: SSH private keys (i.e. digital signature keys)
//! - [`PublicKey`]: SSH public keys (i.e. signature verification keys)
//! - [`SshSig`]: signatures with SSH keys ala `ssh-keygen -Y sign`/`ssh-keygen -Y verify`
//!
//! ### Parsing OpenSSH Public Keys
//!
//! OpenSSH-formatted public keys have the form:
//!
//! ```text
//! <algorithm id> <base64 data> <comment>
//! ```
//!
//! #### Example
//!
//! ```
//! # fn main() -> Result<(), ssh_key::Error> {
//! use ssh_key::PublicKey;
//!
//! let encoded_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com";
//! let public_key = PublicKey::from_openssh(encoded_key)?;
//!
//! // Key attributes
//! assert_eq!(public_key.algorithm(), ssh_key::Algorithm::Ed25519);
//!
//! // Key data: in this example an Ed25519 key
//! if let Some(ed25519_public_key) = public_key.key_data().ed25519() {
//!     assert_eq!(
//!         ed25519_public_key.as_ref(),
//!         &[
//!             0xb3, 0x3e, 0xae, 0xf3, 0x7e, 0xa2, 0xdf, 0x7c, 0xaa, 0x1, 0xd, 0xef, 0xde, 0xa3,
//!             0x4e, 0x24, 0x1f, 0x65, 0xf1, 0xb5, 0x29, 0xa4, 0xf4, 0x3e, 0xd1, 0x43, 0x27, 0xf5,
//!             0xc5, 0x4a, 0xab, 0x62
//!         ]
//!     );
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Parsing OpenSSH Private Keys
//!
//! *NOTE: for more private key usage examples, see the [`private`] module.*
//!
//! OpenSSH-formatted private keys are PEM-encoded and begin with the following:
//!
//! ```text
//! -----BEGIN OPENSSH PRIVATE KEY-----
//! ```
//!
//! Pass an encoded key obtained by the caller rather than embedding private
//! key material in source code:
//!
//! ```
//! use ssh_key::PrivateKey;
//!
//! fn parse_private_key(encoded_key: &str) -> Result<PrivateKey, ssh_key::Error> {
//!     PrivateKey::from_openssh(encoded_key)
//! }
//! ```
//!
//! ## `serde` support
//!
//! When the `serde` feature of this crate is enabled, the [`Certificate`], [`Fingerprint`], and
//! [`PublicKey`] types receive impls of `serde`'s [`Deserialize`][`serde::Deserialize`] and
//! [`Serialize`][`serde::Serialize`] traits.
//!
//! Serializing/deserializing [`PrivateKey`] using `serde` is presently unsupported.

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod authorized_keys;
pub mod private;
pub mod public;

#[cfg(feature = "alloc")]
pub mod certificate;
#[cfg(feature = "alloc")]
pub mod known_hosts;

mod algorithm;
mod error;
mod fingerprint;
mod kdf;

#[cfg(feature = "alloc")]
mod comment;
#[cfg(feature = "std")]
mod dot_ssh;
#[cfg(feature = "ppk")]
mod ppk;
#[cfg(feature = "alloc")]
mod signature;
#[cfg(feature = "alloc")]
mod sshsig;

pub use crate::{
    algorithm::{Algorithm, AssociatedHashAlg, EcdsaCurve, HashAlg, KdfAlg},
    authorized_keys::AuthorizedKeys,
    error::{Error, Result},
    fingerprint::Fingerprint,
    kdf::Kdf,
    private::PrivateKey,
    public::PublicKey,
};
pub use cipher::{self, Cipher};
pub use encoding::{self, pem::LineEnding};
pub use sha2;

#[cfg(feature = "std")]
pub use crate::dot_ssh::DotSsh;
#[cfg(feature = "getrandom")]
pub use cipher::cipher::common::getrandom;
#[cfg(feature = "rand_core")]
pub use rand_core;
#[cfg(feature = "ecdsa")]
pub use sec1;
#[cfg(feature = "alloc")]
pub use {
    crate::{
        algorithm::AlgorithmName,
        certificate::Certificate,
        comment::Comment,
        known_hosts::KnownHosts,
        signature::{Signature, SigningKey},
        sshsig::SshSig,
    },
    encoding::Mpint,
};
