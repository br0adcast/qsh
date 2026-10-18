//! Generation and attempt identifiers for recovery results.

/// The connection and network generation that started a recovery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryEpoch {
    pub connection: u64,
    pub network: u64,
}

/// A complete pass over the eligible addresses within one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SweepId(pub u64);

/// An address within a recovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressId(pub usize);
