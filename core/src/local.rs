//! Device-local state (vault-format §6): device id and the encrypted index cache.

use std::collections::BTreeMap;
use std::io::{Cursor, Write};

use sha2::{Digest, Sha256};

use crate::cbor::{self, Value};
use crate::error::{Error, Result};
use crate::journal::{Chains, DeviceId, State};
use crate::keys::VaultKey;
use crate::object::{open_object, write_object_with, ObjectKind};
use crate::rng::{self, OsRandom, RandomSource};
use crate::store::Store;

fn state_path(store: &Store) -> std::path::PathBuf {
    store.local_dir().join("state.zeo")
}

/// Reads `local/device.id`, creating it with 16 random bytes on first use.
pub fn device_id(store: &Store) -> Result<DeviceId> {
    let path = store.local_dir().join("device.id");
    match std::fs::read(&path) {
        Ok(b) => return b.try_into().map_err(|_| Error::Corrupt),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Io),
    }
    let id = rng::array::<16>(&mut OsRandom)?;
    store.write_atomic(&path, |f| f.write_all(&id).map_err(|_| Error::Io))?;
    Ok(id)
}

/// Cached index plus the bookkeeping for rollback detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalState {
    /// Highest segment `seq` seen per device.
    pub hw: BTreeMap<DeviceId, u64>,
    /// Highest Lamport timestamp seen.
    pub lamport: u64,
    /// Hash over the segment hashes the cache was built from.
    pub journal_hash: [u8; 32],
    pub index: State,
    /// Whether a duress password is set; lives only inside the encrypted state.
    pub duress_enabled: bool,
}

/// SHA-256 over the file hashes of all segments with `seq <= hw[device]`,
/// ordered by device id, then `seq`.
fn journal_hash(chains: &Chains, hw: &BTreeMap<DeviceId, u64>) -> [u8; 32] {
    let mut h = Sha256::new();
    for (device, chain) in chains {
        if let Some(&top) = hw.get(device) {
            for seg in chain.iter().filter(|s| s.seq <= top) {
                h.update(seg.hash);
            }
        }
    }
    h.finalize().into()
}

impl LocalState {
    /// State for a vault without any segments.
    pub fn empty() -> Self {
        Self::build(&Chains::new(), State::new())
    }

    /// Records the current chains together with the `index` folded from them.
    pub fn build(chains: &Chains, index: State) -> Self {
        let hw: BTreeMap<_, _> = chains
            .iter()
            .filter_map(|(d, c)| c.last().map(|s| (*d, s.seq)))
            .collect();
        Self {
            journal_hash: journal_hash(chains, &hw),
            lamport: index.max_t(),
            hw,
            index,
            duress_enabled: false,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let hw = self
            .hw
            .iter()
            .map(|(d, s)| (Value::bytes(d), Value::Uint(*s)))
            .collect();
        let mut map = vec![
            (Value::text("hw"), Value::Map(hw)),
            (Value::text("lamport"), Value::Uint(self.lamport)),
            (Value::text("index"), self.index.to_value()),
            (
                Value::text("journal_hash"),
                Value::bytes(&self.journal_hash),
            ),
        ];
        // Omitted when false, so states without duress keep their previous encoding.
        if self.duress_enabled {
            map.push((Value::text("duress_enabled"), Value::Bool(true)));
        }
        cbor::encode(&Value::Map(map))
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let v = cbor::decode(data)?;
        let get = |k: &str| v.get(k).ok_or(Error::Cbor);
        let mut hw = BTreeMap::new();
        for (k, s) in get("hw")?.as_map().ok_or(Error::Cbor)? {
            let d: DeviceId = k
                .as_bytes()
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Cbor)?;
            hw.insert(d, s.as_u64().ok_or(Error::Cbor)?);
        }
        Ok(Self {
            hw,
            lamport: get("lamport")?.as_u64().ok_or(Error::Cbor)?,
            journal_hash: get("journal_hash")?
                .as_bytes()
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Cbor)?,
            index: State::from_value(get("index")?)?,
            duress_enabled: match v.get("duress_enabled") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return Err(Error::Cbor),
            },
        })
    }
}

/// Writes `local/state.zeo` as an encrypted blob object.
pub fn write_local_state(
    store: &Store,
    vk: &VaultKey,
    vault_id: [u8; 16],
    state: &LocalState,
) -> Result<()> {
    write_local_state_with(store, vk, vault_id, state, &mut OsRandom)
}

/// Random draw order: object_id, then as `write_object_with`.
pub fn write_local_state_with(
    store: &Store,
    vk: &VaultKey,
    vault_id: [u8; 16],
    state: &LocalState,
    rng: &mut impl RandomSource,
) -> Result<()> {
    let payload = state.encode()?;
    let object_id = rng::array::<16>(rng)?;
    let mut w = write_object_with(Vec::new(), vk, vault_id, object_id, ObjectKind::Blob, rng)?;
    w.write_all(&payload)?;
    let file = w.finish()?;
    store.write_atomic(&state_path(store), |f| {
        f.write_all(&file).map_err(|_| Error::Io)
    })
}

/// Returns `None` if there is no cache; a cache that fails to open or parse is an
/// error and the caller rebuilds from the journal.
pub fn read_local_state(
    store: &Store,
    vk: &VaultKey,
    vault_id: [u8; 16],
) -> Result<Option<LocalState>> {
    let file = match std::fs::read(state_path(store)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Io),
    };
    let mut r = open_object(Cursor::new(&file[..]), vk, vault_id, None)?;
    if r.kind() != ObjectKind::Blob {
        return Err(Error::ObjectFormat);
    }
    LocalState::decode(&r.read_all()?).map(Some)
}

/// Fails if a known device has fewer segments than recorded or if the segments up
/// to the recorded high-water marks differ from what the cache was built from.
pub fn check_rollback(local: &LocalState, chains: &Chains) -> Result<()> {
    for (device, &top) in &local.hw {
        let len = chains.get(device).map_or(0, |c| c.len() as u64);
        if len <= top {
            return Err(Error::RollbackDetected);
        }
    }
    if journal_hash(chains, &local.hw) != local.journal_hash {
        return Err(Error::RollbackDetected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::test_util::*;
    use crate::journal::{read_all_chains, write_segment_with};
    use std::fs;

    fn built(s: &Store) -> (LocalState, Chains) {
        let chains = read_all_chains(s, &vk(), VID).unwrap();
        let index = State::fold(chains.values().flatten());
        (LocalState::build(&chains, index), chains)
    }

    #[test]
    fn device_id_is_created_once() {
        let (_d, s) = store();
        let a = device_id(&s).unwrap();
        assert_ne!(a, [0; 16]);
        assert_eq!(device_id(&s).unwrap(), a);
        fs::write(s.local_dir().join("device.id"), b"short").unwrap();
        assert_eq!(device_id(&s), Err(Error::Corrupt));
    }

    #[test]
    fn local_state_round_trip() {
        let (_d, s) = store();
        assert_eq!(read_local_state(&s, &vk(), VID).unwrap(), None);
        write_chain(&s, 1, 2);
        write_chain(&s, 2, 1);
        let (ls, _) = built(&s);
        assert_eq!(ls.hw, BTreeMap::from([([1; 16], 1), ([2; 16], 0)]));
        assert_eq!(ls.lamport, 2);
        write_local_state_with(&s, &vk(), VID, &ls, &mut Counter(3)).unwrap();
        assert_eq!(read_local_state(&s, &vk(), VID).unwrap(), Some(ls.clone()));
        assert_eq!(LocalState::decode(&ls.encode().unwrap()).unwrap(), ls);
        // Another key or vault cannot read it.
        assert!(read_local_state(&s, &crate::keys::VaultKey::from_bytes([1; 32]), VID).is_err());
        assert!(read_local_state(&s, &vk(), [0; 16]).is_err());
        assert_eq!(LocalState::empty().hw.len(), 0);
    }

    #[test]
    fn duress_flag_round_trip_and_default() {
        let mut ls = LocalState::empty();
        let plain = ls.encode().unwrap();
        // Old states carry no key and decode as false.
        assert!(!LocalState::decode(&plain).unwrap().duress_enabled);
        ls.duress_enabled = true;
        let enc = ls.encode().unwrap();
        assert_ne!(enc, plain);
        assert_eq!(LocalState::decode(&enc).unwrap(), ls);
        // A non-boolean value is rejected.
        let mut v = cbor::decode(&plain).unwrap();
        if let Value::Map(m) = &mut v {
            m.push((Value::text("duress_enabled"), Value::Uint(1)));
        }
        assert_eq!(
            LocalState::decode(&cbor::encode(&v).unwrap()),
            Err(Error::Cbor)
        );
    }

    #[test]
    fn decode_rejects_garbage() {
        assert_eq!(LocalState::decode(&[0xbf, 0xff]), Err(Error::Cbor));
        assert_eq!(LocalState::decode(&[0xa0]), Err(Error::Cbor));
    }

    #[test]
    fn rollback_detection() {
        let (_d, s) = store();
        write_chain(&s, 1, 3);
        write_chain(&s, 2, 2);
        let (ls, chains) = built(&s);
        check_rollback(&ls, &chains).unwrap();

        // New segments and new devices are fine.
        write_chain(&s, 3, 1);
        let mut prev = chains[&[1; 16]][2].hash;
        prev = write_segment_with(
            &s,
            &vk(),
            VID,
            [1; 16],
            3,
            prev,
            vec![del(9, 1)],
            &mut Counter(1),
        )
        .unwrap();
        let _ = prev;
        let grown = read_all_chains(&s, &vk(), VID).unwrap();
        check_rollback(&ls, &grown).unwrap();

        // Truncated chain.
        let mut cut = chains.clone();
        cut.get_mut(&[1; 16]).unwrap().pop();
        assert_eq!(check_rollback(&ls, &cut), Err(Error::RollbackDetected));
        // Missing device.
        let mut gone = chains.clone();
        gone.remove(&[2; 16]);
        assert_eq!(check_rollback(&ls, &gone), Err(Error::RollbackDetected));
        // Same length, different content (chain rewritten).
        let mut other = chains.clone();
        other.get_mut(&[2; 16]).unwrap()[1].hash = [0xee; 32];
        assert_eq!(check_rollback(&ls, &other), Err(Error::RollbackDetected));
    }
}
