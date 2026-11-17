#![forbid(unsafe_code)]

mod biometric;
mod cbor;
mod error;
mod export;
mod header;
mod journal;
mod kdf;
mod keys;
mod local;
mod object;
mod recovery;
mod rng;
mod store;
mod stream;
mod vault;

pub use cbor::Value;
pub use error::{Error, Result};
pub use export::{ImportOutcome, ImportSecret};
pub use header::{
    change_password, create, rotate_recovery, set_duress, unlock, unlock_recovery, DuressUpdate,
    UnlockOutcome, VaultHeader,
};
#[cfg(feature = "test-vectors")]
pub use header::{change_password_with, create_with, rotate_recovery_with};
#[cfg(feature = "test-vectors")]
pub use journal::write_segment_with;
pub use journal::{
    clean_album_name, next_t, read_all_chains, read_device_chain, referenced_objects, sweep,
    write_segment, Album, AlbumId, Chains, DeviceId, Item, ItemId, ItemKind, ItemMeta, Op, Segment,
    State, TRASH_RETENTION_MS,
};
pub use kdf::{auth_key, derive_master_key, duress_tag, password_kek, pin_key, KdfParams, PIN_LEN};
pub use keys::VaultKey;
pub use keys::{AuthKey, BioKey, Dek, DuressTag, Kek, MasterKey};
#[cfg(feature = "test-vectors")]
pub use local::write_local_state_with;
pub use local::{check_rollback, device_id, read_local_state, write_local_state, LocalState};
#[cfg(feature = "test-vectors")]
pub use object::write_object_with;
pub use object::{open_object, write_object, ObjectKind, ObjectReader, ObjectWriter};
pub use recovery::{recovery_kek, RecoveryKey};
#[cfg(feature = "test-vectors")]
pub use rng::{RandomSource, SeededRandom};
pub use store::Store;
pub use stream::{StreamDecryptor, StreamEncryptor, CHUNK_SIZE, TAG_LEN};
pub use vault::{
    kdf_calibrate, password_strength, AlbumSummary, GuardedReader, ImportSession, ImportWriter,
    ItemSummary, ObjectId, ObjectRole, RecoveryKeyString, UnlockResult, Vault,
};
