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
//! use p2c_s2c::secp256k1::{Secp256k1, SecretKey};
//! use p2c_s2c::TweakedKeypair;
//!
//! let secp = Secp256k1::new();
//! // Untweaked key
//! let sk: SecretKey = "0101010101010101010101010101010101010101010101010101010101010101"
//!     .parse()
//!     .unwrap();
//! let keypair = sk.keypair(&secp);
//! // P2C-tweaked key
//! let algo = "MyAlgorithm/v1"; // arbitrary string, used for domain separation
//! let prog = b"this is a thing I'm committing in the pubkey";
//! let tweaked_keypair = TweakedKeypair::new(&secp, &sk, None, algo, prog);
//! let tweaked_pk = tweaked_keypair.to_public_key();
//! // Can verify P2C commitment.
//! assert!(tweaked_pk.verify_commitment(&secp, &keypair.public_key(), algo, prog));
//! // S2C-tweaked signature
//! let wit = b"this is a thing I'm committing in the signature";
//! let msg = b"this is the message I'm actually signing";
//! let (sig, nonce) = tweaked_keypair.sign_schnorr(&secp, msg, algo, wit);
//! // Signature verifies as a normal signature
//! let (xonly, _parity) = tweaked_pk.as_public_key().x_only_public_key();
//! secp.verify_schnorr(&sig, msg, &xonly)
//!     .unwrap();
//! // With original nonce, can also verify S2C commitment
//! assert!(tweaked_pk.verify_schnorr_commitment(&secp, &sig, &nonce, algo, wit));
//! ```

mod hashes;
mod signature;

/// Re-export of the `bitcoin_hashes` crate.
pub extern crate bitcoin_hashes;
/// Re-export of the `secp256k1` crate.
pub extern crate secp256k1;

pub use hashes::{Pay2ContractHash, Sign2ContractHash, TweakHash as _};

use secp256k1::ffi::CPtr as _;
use secp256k1::{
    ecdsa, schnorr, Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, Signing,
    Verification,
};

use crate::signature::NonceFnData;

/// A P2C-tweaked public key.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct TweakedPublicKey {
    inner: secp256k1::PublicKey,
}

impl TweakedPublicKey {
    pub fn new<C: Verification>(
        secp: &Secp256k1<C>,
        untweaked_key: &PublicKey,
        algo: &str,
        data: &[u8],
    ) -> Self {
        let tweak_bytes =
            Pay2ContractHash::compute_tweak(untweaked_key, algo, data).to_byte_array();
        let tweak_sc = Scalar::from_be_bytes(tweak_bytes).expect("cryptographically unreachable");
        Self {
            inner: untweaked_key
                .add_exp_tweak(&secp, &tweak_sc)
                .expect("cryptographically unreachable"),
        }
    }

    pub fn verify_commitment<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        untweaked_key: &PublicKey,
        algo: &str,
        data: &[u8],
    ) -> bool {
        *self == Self::new(secp, untweaked_key, algo, data)
    }

    pub fn verify_ecdsa_commitment<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        sig: &ecdsa::Signature,
        untweaked_nonce: &PublicKey,
        algo: &str,
        data: &[u8],
    ) -> bool {
        let sig_ser = sig.serialize_compact();

        let tweak_bytes =
            crate::Sign2ContractHash::compute_tweak(&untweaked_nonce, algo, data).to_byte_array();
        let tweak_sc = Scalar::from_be_bytes(tweak_bytes).expect("cryptographically unreachable");
        let tweaked_nonce = untweaked_nonce
            .add_exp_tweak(secp, &tweak_sc)
            .expect("cryptographically unreachable");
        let nonce_ser = tweaked_nonce.serialize();

        &nonce_ser[1..] == &sig_ser[..32]
    }

    pub fn verify_schnorr_commitment<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        sig: &schnorr::Signature,
        untweaked_nonce: &PublicKey,
        algo: &str,
        data: &[u8],
    ) -> bool {
        let sig_ser = sig.to_byte_array();

        let tweak_bytes =
            crate::Sign2ContractHash::compute_tweak(&untweaked_nonce, algo, data).to_byte_array();
        let tweak_sc = Scalar::from_be_bytes(tweak_bytes).expect("cryptographically unreachable");
        let tweaked_nonce = untweaked_nonce
            .add_exp_tweak(secp, &tweak_sc)
            .expect("cryptographically unreachable");
        let nonce_ser = tweaked_nonce.serialize();

        &nonce_ser[1..] == &sig_ser[..32]
    }

    pub fn as_public_key(&self) -> &PublicKey {
        &self.inner
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TweakedKeypair {
    seckey: SecretKey,
    pubkey: PublicKey,
}

impl TweakedKeypair {
    pub fn new<C: Signing + Verification>(
        secp: &Secp256k1<C>,
        untweaked_key: &SecretKey,
        untweaked_pubkey: Option<PublicKey>,
        algo: &str,
        data: &[u8],
    ) -> Self {
        let untweaked_pubkey = untweaked_pubkey.unwrap_or_else(|| untweaked_key.public_key(secp));

        let tweak_bytes =
            Pay2ContractHash::compute_tweak(&untweaked_pubkey, algo, data).to_byte_array();
        let tweak_sc = Scalar::from_be_bytes(tweak_bytes).expect("cryptographically unreachable");
        let seckey = untweaked_key
            .add_tweak(&tweak_sc)
            .expect("cryptographically unreachable");
        let pubkey = untweaked_pubkey
            .add_exp_tweak(&secp, &tweak_sc)
            .expect("cryptographically unreachable");
        debug_assert_eq!(seckey.public_key(secp), pubkey,);
        Self { seckey, pubkey }
    }

    pub fn to_public_key(&self) -> TweakedPublicKey {
        TweakedPublicKey { inner: self.pubkey }
    }

    pub fn sign_ecdsa<C: Signing + Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: impl Into<Message>,
        s2c_algo: &str,
        s2c_data: &[u8],
    ) -> (ecdsa::Signature, PublicKey) {
        let msg = msg.into();
        let mut data = NonceFnData {
            ctx: secp,
            algo: s2c_algo,
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
                    self.seckey.as_c_ptr(),
                    Some(crate::signature::s2c_ecdsa_nonce_fn::<C>),
                    (&mut data as *mut NonceFnData<C>).cast::<core::ffi::c_void>(),
                ) == 1
            );
            (ret.into(), data.original_nonce.unwrap())
        }
    }

    pub fn sign_schnorr<C: Signing + Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: &[u8],
        s2c_algo: &str,
        s2c_data: &[u8],
    ) -> (schnorr::Signature, PublicKey) {
        let mut data = NonceFnData {
            ctx: secp,
            algo: s2c_algo,
            data: s2c_data,
            original_nonce: None,
        };

        // This is a dumb and inefficient, but we live with it for now. Would be
        // nice for secp256k1::Keypair to have some
        // sort of from_sk_pk_unchecked() method or something
        let keypair = Keypair::from_secret_key(secp, &self.seckey);
        let ext_params = secp256k1::ffi::SchnorrSigExtraParams::new(
            Some(crate::signature::s2c_schnorr_nonce_fn::<C>),
            (&mut data as *mut NonceFnData<C>).cast(),
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
                    keypair.as_c_ptr(),
                    &ext_params,
                ) == 1
            );
            (
                schnorr::Signature::from_byte_array(ret),
                data.original_nonce.unwrap(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ALGO: &str = "TestAlgorithm/v001";
    const TEST_ALGO2: &str = "TestAlgorithm/v002";

    fn test_data() -> (Secp256k1<secp256k1::All>, TweakedKeypair, TweakedPublicKey) {
        let secp = Secp256k1::new();

        // Public, untweaked key.
        let sk: SecretKey = "0101010101010101010101010101010101010101010101010101010101010101"
            .parse()
            .unwrap();
        let keypair = sk.keypair(&secp);

        // Tweaked key (generated in three ways)
        let prog = b"this is a thing I'm committing in the pubkey";
        let tweaked_keypair_1 = TweakedKeypair::new(&secp, &sk, None, TEST_ALGO, prog);
        let tweaked_keypair_2 =
            TweakedKeypair::new(&secp, &sk, Some(keypair.public_key()), TEST_ALGO, prog);
        assert_eq!(tweaked_keypair_1, tweaked_keypair_2);

        let tweaked_pk = TweakedPublicKey::new(&secp, &keypair.public_key(), TEST_ALGO, prog);
        assert_eq!(tweaked_keypair_1.to_public_key(), tweaked_pk);

        assert!(tweaked_pk.verify_commitment(&secp, &keypair.public_key(), TEST_ALGO, prog));

        let prog2 = b"this is NOT a thing I'm committing in the pubkey";
        let tweaked_keypair_3 = TweakedKeypair::new(&secp, &sk, None, TEST_ALGO, prog2);
        assert_ne!(tweaked_keypair_1, tweaked_keypair_3);
        let tweaked_keypair_3 = TweakedKeypair::new(&secp, &sk, None, TEST_ALGO2, prog);
        assert_ne!(tweaked_keypair_1, tweaked_keypair_3);
        let tweaked_keypair_3 = TweakedKeypair::new(&secp, &sk, None, TEST_ALGO2, prog2);
        assert_ne!(tweaked_keypair_1, tweaked_keypair_3);

        // After having done above sanity checks, return the data so we can do a real test.
        (secp, tweaked_keypair_1, tweaked_pk)
    }

    #[test]
    fn end_to_end_ecdsa() {
        let (secp, tweaked_keypair, tweaked_pk) = test_data();

        // Tweaked signature
        let wit = b"this is a thing I'm committing in the signature";
        let msg = Message::from_digest(*b"the sentence is a digest I swear");
        let (sig, nonce) = tweaked_keypair.sign_ecdsa(&secp, msg, TEST_ALGO, wit);

        // Signature verifies as a normal signature
        secp.verify_ecdsa(msg, &sig, &tweaked_pk.as_public_key())
            .unwrap();

        // With original nonce, can also verify commitment
        assert!(tweaked_pk.verify_ecdsa_commitment(&secp, &sig, &nonce, TEST_ALGO, wit));
        assert!(!tweaked_pk.verify_ecdsa_commitment(&secp, &sig, &nonce, TEST_ALGO2, wit));
        let wit2 = b"this is NOT a thing I'm committing in the signature";
        assert!(!tweaked_pk.verify_ecdsa_commitment(&secp, &sig, &nonce, TEST_ALGO, wit2));
        assert!(!tweaked_pk.verify_ecdsa_commitment(&secp, &sig, &nonce, TEST_ALGO2, wit2));
    }

    #[test]
    fn end_to_end_schnorr() {
        let (secp, tweaked_keypair, tweaked_pk) = test_data();

        // Tweaked signature
        let wit = b"this is a thing I'm committing in the signature";
        let msg = b"this is the message I'm actually signing";
        let (sig, nonce) = tweaked_keypair.sign_schnorr(&secp, msg, TEST_ALGO, wit);

        // Signature verifies as a normal signature
        let (xonly, _parity) = tweaked_pk.as_public_key().x_only_public_key();
        secp.verify_schnorr(&sig, msg, &xonly)
            .unwrap();

        // With original nonce, can also verify commitment
        assert!(tweaked_pk.verify_schnorr_commitment(&secp, &sig, &nonce, TEST_ALGO, wit));
        assert!(!tweaked_pk.verify_schnorr_commitment(&secp, &sig, &nonce, TEST_ALGO2, wit));
        let wit2 = b"this is NOT a thing I'm committing in the signature";
        assert!(!tweaked_pk.verify_schnorr_commitment(&secp, &sig, &nonce, TEST_ALGO, wit2));
        assert!(!tweaked_pk.verify_schnorr_commitment(&secp, &sig, &nonce, TEST_ALGO2, wit2));
    }
}
