// SPDX-License-Identifier: LGPL-3.0-or-later

use bitcoin_hashes::{hash_newtype, sha256t, sha256t_tag};

sha256t_tag! {
    /// Tag used for in tagged hash for key tweaking.
    pub struct Pay2ContractTag = hash_str("P2C-S2C/P/1.0");
}

sha256t_tag! {
    /// Tag used for in tagged hash for nonce tweaking.
    pub struct Sign2ContractTag = hash_str("P2C-S2C/S/1.0");
}

hash_newtype! {
    /// Tagged hash used for key tweaking.
    pub struct Pay2ContractHash(sha256t::Hash<Pay2ContractTag>);

    /// Tagged hash used for nonce tweaking.
    pub struct Sign2ContractHash(sha256t::Hash<Sign2ContractTag>);
}

/// A trait describing a hash that can be used to tweak a point in this library.
pub trait TweakHash: bitcoin_hashes::Hash<Bytes = [u8; 32]> + private::Sealed {
    /// The BIP-0340 tag usad for this hash.
    type HashTag: sha256t::Tag;

    fn compute_tweak(key: &secp256k1::PublicKey, algo: &str, data: &[u8]) -> Self {
        use bitcoin_hashes::{sha256t::Tag as _, HashEngine as _};

        assert!(
            algo.len() < 253,
            "algorithm length must be < 253 for now (got {}) (varint support not implemented yet)",
            algo.len(),
        );
        let algo_len_u8 = u8::try_from(algo.len()).expect("see above assertion");

        let mut eng = Self::HashTag::engine();
        eng.input(core::slice::from_ref(&algo_len_u8));
        eng.input(algo.as_bytes());
        eng.input(&key.serialize());
        eng.input(data); // no length prefix OK, since this is the last field

        let bare_hash = sha256t::Hash::<Self::HashTag>::from_engine(eng);
        Self::from_byte_array(bare_hash.to_byte_array())
    }
}

mod private {
    use super::{Pay2ContractHash, Sign2ContractHash};

    pub trait Sealed {}
    impl Sealed for Pay2ContractHash {}
    impl Sealed for Sign2ContractHash {}
}

impl TweakHash for Pay2ContractHash {
    type HashTag = Pay2ContractTag;
}

impl TweakHash for Sign2ContractHash {
    type HashTag = Sign2ContractTag;
}
