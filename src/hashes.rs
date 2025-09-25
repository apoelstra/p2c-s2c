// SPDX-License-Identifier: LGPL-3.0-or-later

use bitcoin_hashes::{hash_newtype, sha256t, sha256t_tag};
use secp256k1::Scalar;

use crate::{AllowedKeysMarker, Full, XOnly};

sha256t_tag! {
    /// Tag used for in tagged hash for key tweaking for full keys.
    pub struct Pay2ContractFullTag = hash_str("P2C-S2C-Full/P/1.0");
}

sha256t_tag! {
    /// Tag used for in tagged hash for nonce tweaking for ECDSA signatures.
    pub struct Sign2ContractFullTag = hash_str("P2C-S2C-Full/S/1.0");
}

sha256t_tag! {
    /// Tag used for in tagged hash for key tweaking for x-only keys.
    pub struct Pay2ContractTag = hash_str("P2C-S2C/P/1.0");
}

sha256t_tag! {
    /// Tag used for in tagged hash for nonce tweaking for BIP-0340 (Schnorr) signatures.
    pub struct Sign2ContractTag = hash_str("P2C-S2C/S/1.0");
}

sha256t_tag! {
    /// Tag used for in tagged hash for key tweaking for full keys.
    pub struct TapTweakTag = hash_str("TapTweak");
}

hash_newtype! {
    /// Tagged hash used for key tweaking for full keys.
    #[derive(Debug)]
    pub struct Pay2ContractFullHash(sha256t::Hash<Pay2ContractFullTag>);

    /// Tagged hash used for nonce tweaking for ECDSA signatures.
    #[derive(Debug)]
    pub struct Sign2ContractFullHash(sha256t::Hash<Sign2ContractFullTag>);

    /// Tagged hash used for key tweaking for x-only keys.
    #[derive(Debug)]
    pub struct Pay2ContractHash(sha256t::Hash<Pay2ContractTag>);

    /// Tagged hash used for nonce tweaking for BIP-0340 (Schnorr) signatures.
    #[derive(Debug)]
    pub struct Sign2ContractHash(sha256t::Hash<Sign2ContractTag>);

    /// Tagged hash for Taproot outputs.
    ///
    /// This is identical to the type of the same name in rust-bitcoin, but has
    /// a slightly different API for use in this crate.
    #[derive(Debug)]
    pub struct TapTweakHash(sha256t::Hash<TapTweakTag>);
}

/// A trait describing a hash that can be used to tweak a point (either a public
/// key or a signature nonce) in this library.
///
/// Using this trait, you can tweak public keys or signatures. If you want to
/// you want to tweak both, you probably want to use a hash which implements the
/// [`PubkeyTweakHash`] trait, which ensures you are using a different domain-separated
/// hash for your P2C commitments and your S2C commitments.
///
/// You can use the [`Pay2ContractHash`] or [`Pay2ContractFullHash`] types for this
/// purpose, which are fine for non-production uses, but for a real application you
/// should define your own hash type.
pub trait TweakHash: bitcoin_hashes::Hash<Bytes = [u8; 32]> {
    /// The BIP-0340 tag usad for this hash.
    type HashTag: sha256t::Tag;

    /// Whether to work with full keys and ECDSA signatures or x-only keys and
    /// BIP-0340 (Schnorr) signatures.
    ///
    /// Must be set to either [`Full`] or [`XOnly`].
    ///
    /// When committing to the key, this determines whether to include its X coordinate.
    /// See the docs for [`AllowedKeysMarker`] for more.
    type AllowedKeys: AllowedKeysMarker;

    /// Computes the tweak that should be added to a given public key to obtain a tweaked public key.
    ///
    /// The serialized key is accepted as a byte slice. However, the tweak computation
    /// does no length-prefixing. The serialized key must therefore either be a fixed
    /// length or contain its own length prefix.
    fn compute_tweak(
        serialized_key: &[u8],
        data: &[u8],
    ) -> Scalar {
        use bitcoin_hashes::{sha256t::Tag as _, HashEngine as _};

        let mut eng = Self::HashTag::engine();
        eng.input(serialized_key);
        eng.input(data); // no length prefix OK, since prefix data was fixed length

        let bare_hash = sha256t::Hash::<Self::HashTag>::from_engine(eng);
        Scalar::from_be_bytes(bare_hash.to_byte_array())
            .expect("cryptographically unreachable")
    }
}

/// Trait describing a hash which can be used specifically to tweak a public key,
/// for use.
pub trait PubkeyTweakHash: TweakHash + bitcoin_hashes::Hash<Bytes = [u8; 32]> {
    /// The commitment type t
    type SignatureTweakHash: TweakHash;
}

impl TweakHash for Pay2ContractHash {
    type HashTag = Pay2ContractTag;
    type AllowedKeys = XOnly;
}

impl PubkeyTweakHash for Pay2ContractHash {
    type SignatureTweakHash = Sign2ContractHash;
}

impl TweakHash for Pay2ContractFullHash {
    type HashTag = Pay2ContractFullTag;
    type AllowedKeys = Full;
}

impl PubkeyTweakHash for Pay2ContractFullHash {
    type SignatureTweakHash = Sign2ContractFullHash;
}

impl TweakHash for Sign2ContractHash {
    type HashTag = Sign2ContractTag;
    type AllowedKeys = XOnly;
}

impl TweakHash for Sign2ContractFullHash {
    type HashTag = Sign2ContractFullTag;
    type AllowedKeys = Full;
}

impl TweakHash for TapTweakHash {
    type HashTag = TapTweakTag;
    type AllowedKeys = XOnly;
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::TweakedKey;
    
    use secp256k1::XOnlyPublicKey;
    
    #[test]
    #[rustfmt::skip]
    fn taproot() {
        /* Computable as
        let dummy_hash = bitcoin::TapNodeHash::from_script(
            bitcoin::Script::new(),
            bitcoin::taproot::LeafVersion::TapScript,
        );
        */
        let dummy_hash = [
            0x83, 0xd9, 0x56, 0xa5, 0xb3, 0x61, 0x09, 0xf8,
            0xf6, 0x67, 0xaa, 0x9b, 0x36, 0x6e, 0x84, 0x79,
            0x94, 0x2e, 0x32, 0x39, 0x64, 0x55, 0xb5, 0xf4,
            0x3b, 0x6d, 0xf9, 0x17, 0x76, 0x8e, 0x4d, 0x45,
        ];

        let untweaked: XOnlyPublicKey = "1112131405060708010203040506070801020304050607080102030405060708".parse().unwrap();
        let p2c_tweaked = TweakedKey::<_, TapTweakHash>::new(&untweaked, &dummy_hash);
        assert_eq!(
            p2c_tweaked.as_inner().serialize(),
            [
                0x1c, 0xf7, 0xe5, 0x0f, 0x0b, 0xbf, 0x9a, 0x05,
                0xb1, 0x2f, 0x09, 0x71, 0x5d, 0x4f, 0x31, 0x4a,
                0x6f, 0xa9, 0x4c, 0xc7, 0xe5, 0xcb, 0xf4, 0x76,
                0xf9, 0xeb, 0x1d, 0x01, 0x4e, 0xf4, 0xac, 0xef,
            ],
        );

        /* The same key can be computed from
        let secp = secp256k1::Secp256k1::new();
        let bitcoin_tweaked = bitcoin::taproot::TaprootSpendInfo::new_key_spend(&secp, untweaked, Some(bitcoin::TapNodeHash::from_byte_array(dummy_hash)));
        */
    }
}
