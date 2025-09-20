// SPDX-License-Identifier: LGPL-3.0-or-later

//! Pay-to-Contract / Sign-to-Contract
//!
//! This library provides support for the Pay-to-Contract (P2C) construction, which
//! transforms secp256k1 signing keys into cryptographic commitments to arbitrary
//! data, as well as the Sign-to-Contract (S2C) construction, which does the same
//! for ECDSA or BIP-0340 (Schnorr) signatures produced by the same keys.
//!
//! It is intended for use within
//! [smart contracts unchained](https://zmnscpxj.github.io/bitcoin/unchained.html)
//! in which S2C signatures are used with P2C keys. However, in principle the two
//! constructions are indepedent and there is no need to use them together.
//!
//! # Example (BIP-0340 Signing)
//!
//! ```rust
//! use p2c_s2c::secp256k1::{Secp256k1, SecretKey, Keypair};
//! use p2c_s2c::{TweakedKey, Pay2ContractHash};
//!
//! let secp = Secp256k1::new();
//!
//! // Untweaked key
//! let sk: SecretKey = "0101010101010101010101010101010101010101010101010101010101010101"
//!     .parse()
//!     .unwrap();
//! let keypair = sk.keypair(&secp);
//!
//! // P2C-tweaked signing key
//! let prog = b"this is a thing I'm committing in the pubkey";
//! let tweaked_keypair = TweakedKey::<_, Pay2ContractHash>::new(&keypair, prog);
//! let tweaked_xpk = tweaked_keypair.to_x_only_public_key();
//!
//! // Alternately, can compute the public key from the untweaked public key.
//! let untweaked_xpk = keypair.x_only_public_key().0;
//! assert_eq!(
//!     tweaked_xpk,
//!     TweakedKey::new(&untweaked_xpk, prog),
//! );
//!
//! // Can verify P2C commitment.
//! assert!(tweaked_xpk.verify_key_commitment(&untweaked_xpk, prog));
//!
//! // S2C-tweaked signature
//! let wit = b"this is a thing I'm committing in the signature";
//! let msg = b"this is the message I'm actually signing";
//! let (sig, nonce) = tweaked_keypair.sign_schnorr(&secp, msg, wit);
//!
//! // Signature verifies as a normal signature
//! secp.verify_schnorr(&sig, msg, tweaked_xpk.as_inner())
//!     .unwrap();
//!
//! // With original nonce, can also verify S2C commitment
//! assert!(tweaked_xpk.verify_schnorr_commitment(&sig, &nonce, wit));
//! ```

mod hashes;
mod key;
mod signature;

/// Re-export of the `bitcoin_hashes` crate.
pub extern crate bitcoin_hashes;
/// Re-export of the `secp256k1` crate.
pub extern crate secp256k1;

pub use crate::hashes::{Pay2ContractHash, Sign2ContractHash, Pay2ContractFullHash, Sign2ContractFullHash,TweakHash, PubkeyTweakHash};
pub use crate::key::{TweakableKey, TweakedKey};

use secp256k1::ffi::CPtr as _;
use secp256k1::{
    ecdsa, schnorr, Keypair, Message, PublicKey, Secp256k1, SecretKey, Signing,
    Verification, XOnlyPublicKey,
};

use crate::signature::NonceFnData;

impl<H: TweakHash<AllowedKeys = XOnly>> TweakedKey<Keypair, H> {
    /// Tweaks a [`SecretKey`] using P2C to create a new [`TweakedKeypair`].
    ///
    /// If you are calling this method, there may be a more efficient way to factor
    /// your code to obtain a [`Keypair`] and to call [`Self::new`] instead.
    /// This will avoid re-computing the public key corresponding to your secret key.
    pub fn from_secret_key(
        untweaked_key: &SecretKey,
        data: &[u8],
    ) -> Self {
        // FIXME: in rust-secp 0.33 we will be able to avoid these
        let secp = Secp256k1::signing_only();
        let untweaked = Keypair::from_secret_key(&secp, untweaked_key);
        Self::new(&untweaked, data)
    }

    /// The public part of the keypair.
    ///
    /// This returns a [`TweakedKey`]; if you want a [`XOnlyPublicKey`], you
    /// must call `as_inner` on the returned value.
    pub fn to_x_only_public_key(&self) -> TweakedKey<XOnlyPublicKey, H> {
        self.map_ref(|kp| kp.x_only_public_key().0)
    }

    /// Produces an BIP-0340 (Schnorr) signature which S2C-commits to the given data.
    pub fn sign_schnorr<C: Signing + Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: &[u8],
        s2c_data: &[u8],
    ) -> (schnorr::Signature, XOnlyPublicKey)
    where
        H: PubkeyTweakHash,
        H::SignatureTweakHash: TweakHash<AllowedKeys = XOnly>,
    {
        let mut data = NonceFnData {
            ctx: secp,
            data: s2c_data,
            original_nonce: None,
        };

        let ext_params = secp256k1::ffi::SchnorrSigExtraParams::new(
            Some(crate::signature::s2c_schnorr_nonce_fn::<C, H::SignatureTweakHash>),
            core::ptr::addr_of_mut!(data).cast(),
        );

        unsafe {
            // SAFETY: ffi call; all parameters chosen correctly
            let mut ret = [0u8; secp256k1::constants::SCHNORR_SIGNATURE_SIZE];
            assert!(
                secp256k1::ffi::secp256k1_schnorrsig_sign_custom(
                    secp.ctx().as_ptr().cast_const(),
                    ret.as_mut_ptr(),
                    msg.as_c_ptr(),
                    msg.len(),
                    self.as_inner().as_c_ptr(),
                    &ext_params,
                ) == 1
            );
            (
                schnorr::Signature::from_byte_array(ret),
                data.original_nonce.unwrap().x_only_public_key().0,
            )
        }
    }
}

impl<H: TweakHash<AllowedKeys = Full>> TweakedKey<(SecretKey, PublicKey), H> {
    /// The public part of the keypair.
    ///
    /// This returns a [`TweakedKey`]; if you want a [`XOnlyPublicKey`], you
    /// must call `as_inner` on the returned value.
    pub fn to_public_key(&self) -> TweakedKey<PublicKey, H> {
        self.map_ref(|kp| kp.1)
    }

    /// Produces an ECDSA signature which S2C-commits to the given data.
    pub fn sign_ecdsa<C: Signing + Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: impl Into<Message>,
        s2c_data: &[u8],
    ) -> (ecdsa::Signature, PublicKey)
    where
        H: PubkeyTweakHash,
        H::SignatureTweakHash: TweakHash<AllowedKeys = Full>,
    {
        let msg = msg.into();
        let mut data = NonceFnData {
            ctx: secp,
            data: s2c_data,
            original_nonce: None,
        };

        unsafe {
            // SAFETY: ffi call; all parameters chosen correctly
            let mut ret = secp256k1::ffi::Signature::new();
            assert!(
                secp256k1::ffi::secp256k1_ecdsa_sign(
                    secp.ctx().as_ptr().cast_const(),
                    &mut ret,
                    msg.as_c_ptr(),
                    self.as_inner().0.as_c_ptr(),
                    Some(crate::signature::s2c_ecdsa_nonce_fn::<C, H::SignatureTweakHash>),
                    core::ptr::addr_of_mut!(data).cast(),
                ) == 1
            );
            (ret.into(), data.original_nonce.unwrap())
        }
    }
}

/// Trait simulating a type-level boolean.
///
/// This trait is only implemented for [`Full`] and [`XOnly`], depending
/// whether you want to work with BIP-0340 (Schnorr) or ECDSA signatures.
///
/// We do not allow using the same tweaked hash with both types of signatures.
/// It is inadvisable to do so, because the tweaks are computed slightly
/// differently in each case (for full keys we hash the prefix bit, while for
/// x-only keys we hash only the x coordinate), which may lead to surprising
/// behavior.
///
/// Please file an issue if you have a use-case for this.
pub trait AllowedKeysMarker: private::Sealed {
    /// The length of a serialized key, in bytes.
    type Serialized: bitcoin_hashes::IsByteArray;
}

/// Only allow full keys and ECDSA signatures.
pub enum Full {}
/// Only allow x-only keys and BIP-0340 (Schnorr) signatures.
pub enum XOnly {}

impl AllowedKeysMarker for Full {
    type Serialized = [u8; 33];
}

impl AllowedKeysMarker for XOnly {
    type Serialized = [u8; 32];
}

mod private {
    pub trait Sealed {}
    impl Sealed for super::Full {}
    impl Sealed for super::XOnly {}
}


#[cfg(test)]
mod tests_x_only {
    use super::*;

    fn test_data() -> (
        Secp256k1<secp256k1::All>,
        TweakedKey<Keypair, Pay2ContractHash>,
        TweakedKey<XOnlyPublicKey, Pay2ContractHash>,
    ) {
        let secp = Secp256k1::new();

        // Public, untweaked key.
        let sk: SecretKey = "0101010101010101010101010101010101010101010101010101010101010101"
            .parse()
            .unwrap();
        let keypair = sk.keypair(&secp);
        let (x_only, _parity) = keypair.x_only_public_key();

        // Tweaked key (generated in three ways)
        let prog = b"this is a thing I'm committing in the pubkey";
        let tweaked_keypair_1 = TweakedKey::from_secret_key(&sk, prog);
        let tweaked_keypair_2 = TweakedKey::new(&keypair, prog);
        assert_eq!(tweaked_keypair_1, tweaked_keypair_2);

        let tweaked_pk = tweaked_keypair_1.to_x_only_public_key();
        let tweaked_pk_1 = TweakedKey::new(&x_only, prog);
        assert_eq!(tweaked_pk, tweaked_pk_1);
        
        assert!(tweaked_pk.verify_key_commitment(&x_only,  prog));

        let prog2 = b"this is NOT a thing I'm committing in the pubkey";
        let tweaked_keypair_3 = TweakedKey::from_secret_key(&sk, prog2);
        assert_ne!(tweaked_keypair_1, tweaked_keypair_3);
        let tweaked_keypair_3 = TweakedKey::from_secret_key(&sk, prog2);
        assert_ne!(tweaked_keypair_1, tweaked_keypair_3);

        // After having done above sanity checks, return the data so we can do a real test.
        (secp, tweaked_keypair_1, tweaked_pk)
    }

    #[test]
    fn end_to_end_schnorr() {
        let (secp, tweaked_keypair, tweaked_pk) = test_data();

        // Tweaked signature
        let wit = b"this is a thing I'm committing in the signature";
        let msg = b"this is the message I'm actually signing";
        let (sig, nonce) = tweaked_keypair.sign_schnorr(&secp, msg, wit);

        // Signature verifies as a normal signature
        let xonly = tweaked_pk.as_inner();
        secp.verify_schnorr(&sig, msg, &xonly)
            .unwrap();

        // With original nonce, can also verify commitment
        assert!(tweaked_pk.verify_schnorr_commitment(&sig, &nonce, wit));
        let wit2 = b"this is NOT a thing I'm committing in the signature";
        assert!(!tweaked_pk.verify_schnorr_commitment(&sig, &nonce, wit2));
    }
}

#[cfg(test)]
mod tests_ecdsa {
    use super::*;

    fn test_data() -> (
        Secp256k1<secp256k1::All>,
        TweakedKey<(SecretKey, PublicKey), Pay2ContractFullHash>,
        TweakedKey<PublicKey, Pay2ContractFullHash>,
    ) {
        let secp = Secp256k1::new();

        // Public, untweaked key.
        let sk: SecretKey = "0101010101010101010101010101010101010101010101010101010101010101"
            .parse()
            .unwrap();
        let pk = sk.public_key(&secp);

        // Tweaked key (generated in three ways)
        let prog = b"this is a thing I'm committing in the pubkey";
        let tweaked_keypair = TweakedKey::new(&(sk, pk), prog);

        let tweaked_pk = tweaked_keypair.to_public_key();
        let tweaked_pk_1 = TweakedKey::new(&pk, prog);
        assert_eq!(tweaked_pk, tweaked_pk_1);
        
        assert!(tweaked_pk.verify_key_commitment(&pk, prog));

        let prog2 = b"this is NOT a thing I'm committing in the pubkey";
        let tweaked_keypair_2 = TweakedKey::new(&(sk, pk), prog2);
        assert_ne!(tweaked_keypair, tweaked_keypair_2);
        let tweaked_keypair_2 = TweakedKey::new(&(sk, pk), prog2);
        assert_ne!(tweaked_keypair, tweaked_keypair_2);

        // After having done above sanity checks, return the data so we can do a real test.
        (secp, tweaked_keypair, tweaked_pk)
    }

    #[test]
    fn end_to_end_ecdsa() {
        let (secp, tweaked_keypair, tweaked_pk) = test_data();

        // Tweaked signature
        let wit = b"this is a thing I'm committing in the signature";
        let msg = Message::from_digest(*b"the sentence is a digest I swear");
        let (sig, nonce) = tweaked_keypair.sign_ecdsa(&secp, msg, wit);

        // Signature verifies as a normal signature
        let pk= tweaked_pk.as_inner();
        secp.verify_ecdsa(msg, &sig, &pk)
            .unwrap();

        // With original nonce, can also verify commitment
        assert!(tweaked_pk.verify_ecdsa_commitment(&sig, &nonce, wit));
        let wit2 = b"this is NOT a thing I'm committing in the signature";
        assert!(!tweaked_pk.verify_ecdsa_commitment(&sig, &nonce, wit2));
    }
}
