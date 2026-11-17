//! Flat error type for Swift; one variant per core error, no payloads.

use zeroenclave_core::Error;

#[derive(Debug, thiserror::Error, uniffi::Error, PartialEq, Eq)]
pub enum ZeError {
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("KDF parameters out of range")]
    InvalidKdfParams,
    #[error("recovery key has an invalid format")]
    RecoveryKeyFormat,
    #[error("recovery key checksum mismatch")]
    RecoveryKeyChecksum,
    #[error("random number generator failure")]
    Rng,
    #[error("key derivation failed")]
    Kdf,
    #[error("vault header has an invalid format")]
    HeaderFormat,
    #[error("vault header tampered")]
    HeaderTampered,
    #[error("wrong recovery key")]
    WrongRecoveryKey,
    #[error("encryption failed")]
    Crypto,
    #[error("duress password must differ from the master password")]
    DuressEqualsPassword,
    #[error("object file has an invalid format")]
    ObjectFormat,
    #[error("object belongs to a different vault or has a different id")]
    ObjectMismatch,
    #[error("object is corrupt or does not belong to this vault")]
    Corrupt,
    #[error("object exceeds the maximum size")]
    TooLarge,
    #[error("range outside the object")]
    OutOfRange,
    #[error("CBOR data is malformed or not canonical")]
    Cbor,
    #[error("journal is corrupt or violates the chain rules")]
    JournalCorrupt,
    #[error("journal rollback detected")]
    RollbackDetected,
    #[error("file already exists")]
    Exists,
    #[error("vault is locked")]
    Locked,
    #[error("vault is read-only")]
    ReadOnly,
    #[error("not found")]
    NotFound,
    #[error("not a vault")]
    NotAVault,
    #[error("wrong password")]
    WrongPassword,
    #[error("invalid argument")]
    InvalidInput,
    #[error("export file is malformed or has been tampered with")]
    ExportFormat,
    #[error("export contains a file that differs from the existing one")]
    ExportConflict,
    #[error("export belongs to a different vault")]
    DifferentVault,
    #[error("biometric slot is invalid or does not match this vault")]
    BiometricInvalid,
    #[error("biometric unlock expired; the master password is required")]
    BiometricExpired,
    #[error("wrong PIN; the master password is required")]
    PinInvalid,
    #[error("PIN unlock expired; the master password is required")]
    PinExpired,
    #[error("I/O error")]
    Io,
}

impl From<Error> for ZeError {
    fn from(e: Error) -> Self {
        match e {
            Error::EmptyPassword => Self::EmptyPassword,
            Error::InvalidKdfParams => Self::InvalidKdfParams,
            Error::RecoveryKeyFormat => Self::RecoveryKeyFormat,
            Error::RecoveryKeyChecksum => Self::RecoveryKeyChecksum,
            Error::Rng => Self::Rng,
            Error::Kdf => Self::Kdf,
            Error::HeaderFormat => Self::HeaderFormat,
            Error::HeaderTampered => Self::HeaderTampered,
            Error::WrongRecoveryKey => Self::WrongRecoveryKey,
            Error::Crypto => Self::Crypto,
            Error::DuressEqualsPassword => Self::DuressEqualsPassword,
            Error::ObjectFormat => Self::ObjectFormat,
            Error::ObjectMismatch => Self::ObjectMismatch,
            Error::Corrupt => Self::Corrupt,
            Error::TooLarge => Self::TooLarge,
            Error::OutOfRange => Self::OutOfRange,
            Error::Cbor => Self::Cbor,
            Error::JournalCorrupt => Self::JournalCorrupt,
            Error::RollbackDetected => Self::RollbackDetected,
            Error::Exists => Self::Exists,
            Error::Locked => Self::Locked,
            Error::ReadOnly => Self::ReadOnly,
            Error::NotFound => Self::NotFound,
            Error::NotAVault => Self::NotAVault,
            Error::WrongPassword => Self::WrongPassword,
            Error::InvalidInput => Self::InvalidInput,
            Error::ExportFormat => Self::ExportFormat,
            Error::ExportConflict => Self::ExportConflict,
            Error::DifferentVault => Self::DifferentVault,
            Error::BiometricInvalid => Self::BiometricInvalid,
            Error::BiometricExpired => Self::BiometricExpired,
            Error::PinInvalid => Self::PinInvalid,
            Error::PinExpired => Self::PinExpired,
            Error::Io => Self::Io,
        }
    }
}
