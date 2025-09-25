// SPDX-License-Identifier: LGPL-3.0-or-later

//! Tweakable Keys
//!
//! This module contains the [`TweakableKey`] trait, which is implemented for
//! public keytypes and keypair types. The trait constrains each key type to
//! be used either as a full key or an x-only key, and this library will
//! ensure that tweaks are only computed with a hash constrained to the
//! same key type.
//!
//! This constraint is there to help maintain domain separation of hashes. Of
//! course, it is possible to override these checks by converting keytypes
//! and so on, but we highly discourage this.
//!


use core::marker::PhantomData;

use secp256k1::{Secp256k1, PublicKey, XOnlyPublicKey, Keypair, SecretKey};
use secp256k1::{ecdsa, schnorr};

use crate::{AllowedKeysMarker, Full, XOnly, PubkeyTweakHash, TweakHash};

/// A public key or keypair that can be tweaked for use in P2C or S2C.
pub trait TweakableKey {
    /// Whether to work with full keys and ECDSA signatures or x-only keys and
    /// BIP-0340 (Schnorr) signatures.
    ///
    /// Must be set to either [`Full`] or [`XOnly`].
    ///
    /// When committing to the key, this determines whether to include its X coordinate.
    /// See the docs for [`AllowedKeysMarker`] for more.
    type AllowedKeys: AllowedKeysMarker;

    /// Serializes the key as bytes.
    fn serialize(&self) -> <Self::AllowedKeys as AllowedKeysMarker>::Serialized;

    /// Adds a tweak to the key.
    ///
    /// This method should probably not be used directly, since it returns a
    /// [`Self`]. You probably want to use a constructor for `TweakedKey`
    /// instead.
    ///
    /// # Panics
    ///
    /// May panic on a negligible set of inputs (e.g. scalars that, when added
    /// to the key, would yield the point at infinity). If this method is
    /// called with the output of a cryptograhic hash function which was provided
    /// the original key as input, no panics are possible.
    fn add_tweak(&self, tweak: &secp256k1::Scalar) -> Self;
}

impl TweakableKey for PublicKey {
    type AllowedKeys = Full;

    fn serialize(&self) -> [u8; 33] { self.serialize() }

    fn add_tweak(&self, tweak: &secp256k1::Scalar) -> Self {
        // FIXME: in rust-secp 0.33 we will be able to avoid these
        let secp = Secp256k1::verification_only();
        self.add_exp_tweak(&secp, tweak).expect("cryptographically unreachable")
    }
}

impl TweakableKey for XOnlyPublicKey {
    type AllowedKeys = XOnly;

    fn serialize(&self) -> [u8; 32] { self.serialize() }

    fn add_tweak(&self, tweak: &secp256k1::Scalar) -> Self {
        // FIXME: in rust-secp 0.33 we will be able to avoid these
        let secp = Secp256k1::verification_only();
        let (xonly, _parity) = XOnlyPublicKey::add_tweak(*self, &secp, tweak)
            .expect("cryptographically unreachable");
        xonly
    }
}

impl TweakableKey for Keypair {
    type AllowedKeys = XOnly;

    fn serialize(&self) -> [u8; 32] { self.x_only_public_key().0.serialize() }

    fn add_tweak(&self, tweak: &secp256k1::Scalar) -> Self {
        // FIXME: in rust-secp 0.33 we will be able to avoid these
        let secp = Secp256k1::verification_only();
        self.add_xonly_tweak(&secp, tweak)
            .expect("cryptographically unreachable")
    }
}

impl TweakableKey for (SecretKey, PublicKey) {
    type AllowedKeys = Full;

    fn serialize(&self) -> [u8; 33] { self.1.serialize() }

    fn add_tweak(&self, tweak: &secp256k1::Scalar) -> Self {
        (
            self.0.add_tweak(tweak)
                .expect("cryptographically unreachable"),
            self.1.add_tweak(tweak),
        )
    }
}

/// A tweaked key.
///
/// This is a thin wrapper around a tweaked key, which ties the key to
/// the hash algorithm used to tweak it. You can access the underlying
/// key with [`Self::as_inner`] or by casting.
#[repr(transparent)]
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TweakedKey<K, H> {
    inner: K,
    phantom: PhantomData<H>,
}

impl<K, H> TweakedKey<K, H> {
    /// The underlying tweaked key.
    pub fn as_inner(&self) -> &K { &self.inner}

    /// Applies some function to the underlying key.
    pub fn map_ref<L>(&self, f: impl FnOnce(&K) -> L) -> TweakedKey<L, H> {
        TweakedKey {
            inner: f(&self.inner),
            phantom: self.phantom,
        }
    }
}

impl<K, H> TweakedKey<K, H>
where
    K: TweakableKey,
    H: TweakHash<AllowedKeys = K::AllowedKeys>,
{
    /// Tweaks a public key to create a new [`TweakedKey`].
    pub fn new(
        untweaked_key: &K,
        data: &[u8],
    ) -> Self {
        let tweak = H::compute_tweak(untweaked_key.serialize().as_ref(), data);
        let inner = untweaked_key.add_tweak(&tweak);
        Self { inner, phantom: PhantomData }
    }

    /// Verifies that this [`TweakedKey`] was created with a specific untweaked key
    /// and commitment data.
    pub fn verify_key_commitment(
        &self,
        untweaked_key: &K,
        data: &[u8],
    ) -> bool
    where Self: PartialEq
    {
        *self == Self::new(untweaked_key, data)
    }

    /// Verifies that an ECDSA signature created with this key has a S2C commitment with the
    /// specified untweaked nonce and data.
    pub fn verify_ecdsa_commitment(
        &self,
        sig: &ecdsa::Signature,
        untweaked_nonce: &PublicKey,
        data: &[u8],
    ) -> bool
    where
        H: PubkeyTweakHash<AllowedKeys = Full>,
        H::SignatureTweakHash: TweakHash<AllowedKeys = Full>,
    {
        let tweaked_nonce = TweakedKey::<_, H::SignatureTweakHash>::new(untweaked_nonce, data);
        tweaked_nonce.inner.serialize()[1..] == sig.serialize_compact()[..32]
    }

    /// Verifies that a BIP-0340 (Schnorr) signature created with this key has a S2C commitment
    /// with the specified untweaked nonce and data.
    pub fn verify_schnorr_commitment<>(
        &self,
        sig: &schnorr::Signature,
        untweaked_nonce: &XOnlyPublicKey,
        data: &[u8],
    ) -> bool
    where
        H: PubkeyTweakHash<AllowedKeys = XOnly>,
        H::SignatureTweakHash: TweakHash<AllowedKeys = XOnly>,
    {
        let tweaked_nonce = TweakedKey::<_, H::SignatureTweakHash>::new(untweaked_nonce, data);
        tweaked_nonce.inner.serialize() == sig.to_byte_array()[..32]
    }
}

