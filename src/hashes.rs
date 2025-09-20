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
}

/// A trait describing a hash that can be used to tweak a point (either a public
/// key or a signature nonce) in this library.
///
/// Using this trait, you can tweak public keys or signatures independently. If
/// you want to use both features together, you probably want to use a public key
/// which implements the [`PubkeyTweakHash`] trait.
///
/// This method provides a large number of utility methods. It is likely that you
/// don't need to call any of them directly; instead, call the methods implemented
/// on [`TweakedPublicKey`] or [`TweakedKeypair`]. In particular, many methods can
/// be called which will panic if [`Self::AllowedKeys`] is the wrong value. This
/// is because of a [longstanding bug in the Rust language](https://github.com/rust-lang/rust/issues/20041).
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
