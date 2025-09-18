// SPDX-License-Identifier: LGPL-3.0-or-later

//! Pay-to-Contract Sign-to-Contract

mod hashes;
mod signature;

pub use hashes::{Pay2ContractHash, Sign2ContractHash, TweakHash as _};

use crate::signature::NonceFnData;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct TweakedPublicKey {
    inner: secp256k1::PublicKey,
}

impl TweakedPublicKey {
    pub fn new<C: secp256k1::Verification>(
        secp: &secp256k1::Secp256k1<C>,
        untweaked_key: &secp256k1::PublicKey,
        algo: &str,
        data: &[u8],
    ) -> Self {
        let tweak_bytes = Pay2ContractHash::compute_tweak(untweaked_key, algo, data).to_byte_array();
        let tweak_sc = secp256k1::Scalar::from_be_bytes(tweak_bytes).expect("cryptographically unreachable");
        Self {
            inner: untweaked_key.add_exp_tweak(&secp, &tweak_sc).expect("cryptographically unreachable"),
        }
    }

    pub fn verify_commitment<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        untweaked_key: &secp256k1::PublicKey,
        algo: &str,
        data: &[u8],
    ) -> bool {
        *self == Self::new(secp, untweaked_key, algo, data)
    }

    pub fn verify_ecdsa_commitment<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        sig: &secp256k1::ecdsa::Signature,
        untweaked_nonce: &secp256k1::PublicKey,
        algo: &str,
        data: &[u8],
    ) -> bool {
        let sig_ser = sig.serialize_compact();

        let tweak_bytes = crate::Sign2ContractHash::compute_tweak(&untweaked_nonce, algo, data).to_byte_array();
        let tweak_sc = secp256k1::Scalar::from_be_bytes(tweak_bytes).expect("cryptographically unreachable");
        let tweaked_nonce = untweaked_nonce.add_exp_tweak(secp, &tweak_sc).expect("cryptographically unreachable");
        let nonce_ser = tweaked_nonce.serialize();

        &nonce_ser[1..] == &sig_ser[..32]
    }

    pub fn as_public_key(&self) -> &secp256k1::PublicKey {
        &self.inner
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TweakedKeypair {
    seckey: secp256k1::SecretKey,
    pubkey: secp256k1::PublicKey,
}

impl TweakedKeypair {
    pub fn new<C: secp256k1::Signing + secp256k1::Verification>(
        secp: &secp256k1::Secp256k1<C>,
        untweaked_key: &secp256k1::SecretKey,
        untweaked_pubkey: Option<secp256k1::PublicKey>,
        algo: &str,
        data: &[u8],
    ) -> Self {
        let untweaked_pubkey = untweaked_pubkey.unwrap_or_else(
            || untweaked_key.public_key(secp)
        );

        let tweak_bytes = Pay2ContractHash::compute_tweak(&untweaked_pubkey, algo, data).to_byte_array();
        let tweak_sc = secp256k1::Scalar::from_be_bytes(tweak_bytes).expect("cryptographically unreachable");
        let seckey = untweaked_key.add_tweak(&tweak_sc).expect("cryptographically unreachable");
        let pubkey = untweaked_pubkey.add_exp_tweak(&secp, &tweak_sc).expect("cryptographically unreachable");
        debug_assert_eq!(
            seckey.public_key(secp),
            pubkey,
        );
        Self { seckey, pubkey }
    }

    pub fn public_key(&self) -> TweakedPublicKey {
        TweakedPublicKey {
            inner: self.pubkey,
        }
    }

    pub fn sign_ecdsa<C: secp256k1::Signing>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        msg: impl Into<secp256k1::Message>,
        s2c_algo: &str,
        s2c_data: &[u8],
    ) -> (secp256k1::ecdsa::Signature, secp256k1::PublicKey) {
        use secp256k1::ffi::CPtr as _;
        
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
            assert!(secp256k1::ffi::secp256k1_ecdsa_sign(
                secp.ctx().as_ptr().cast_const(),
                &mut ret,
                msg.as_c_ptr(),
                self.seckey.as_c_ptr(),
                Some(crate::signature::s2c_ecdsa_nonce_fn::<C>),
                (&mut data as *mut NonceFnData<C>).cast::<core::ffi::c_void>(),
            ) == 1);
            (ret.into(), data.original_nonce.unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ALGO: &str = "TestAlgorithm/v001";
    const TEST_ALGO2: &str = "TestAlgorithm/v002";
    
    #[test]
    fn end_to_end_sign() {
        let secp = secp256k1::Secp256k1::new();

        // Public, untweaked key.
        let sk: secp256k1::SecretKey = "0101010101010101010101010101010101010101010101010101010101010101"
            .parse().unwrap();
        let keypair = sk.keypair(&secp);

        // Tweaked key (generated in three ways)
        let prog = b"this is a thing I'm committing in the pubkey";
        let tweaked_keypair_1 = TweakedKeypair::new(&secp, &sk, None, TEST_ALGO, prog);
        let tweaked_keypair_2 = TweakedKeypair::new(&secp, &sk, Some(keypair.public_key()), TEST_ALGO, prog);
        assert_eq!(tweaked_keypair_1, tweaked_keypair_2);

        let tweaked_pk = TweakedPublicKey::new(&secp, &keypair.public_key(), TEST_ALGO, prog);
        assert_eq!(tweaked_keypair_1.public_key(), tweaked_pk);

        assert!(tweaked_pk.verify_commitment(&secp, &keypair.public_key(), TEST_ALGO, prog));

        let prog2 = b"this is NOT a thing I'm committing in the pubkey";
        let tweaked_keypair_3 = TweakedKeypair::new(&secp, &sk, None, TEST_ALGO, prog2);
        assert_ne!(tweaked_keypair_1, tweaked_keypair_3);
        let tweaked_keypair_3 = TweakedKeypair::new(&secp, &sk, None, TEST_ALGO2, prog);
        assert_ne!(tweaked_keypair_1, tweaked_keypair_3);
        let tweaked_keypair_3 = TweakedKeypair::new(&secp, &sk, None, TEST_ALGO2, prog2);
        assert_ne!(tweaked_keypair_1, tweaked_keypair_3);

        // Tweaked signature
        let wit = b"this is a thing I'm committing in the signature";
        let msg = secp256k1::Message::from_digest(*b"the sentence is a digest I swear");
        let (sig, nonce) = tweaked_keypair_1.sign_ecdsa(
            &secp,
            msg,
            TEST_ALGO,
            wit,
        );

        // Signature verifies as a normal signature
        secp.verify_ecdsa(msg, &sig, &tweaked_pk.as_public_key()).unwrap();

        // With original nonce, can also verify commitment
        assert!(tweaked_pk.verify_ecdsa_commitment(&secp, &sig, &nonce, TEST_ALGO, wit));
        assert!(!tweaked_pk.verify_ecdsa_commitment(&secp, &sig, &nonce, TEST_ALGO2, wit));
        let wit2 = b"this is NOT a thing I'm committing in the signature";
        assert!(!tweaked_pk.verify_ecdsa_commitment(&secp, &sig, &nonce, TEST_ALGO, wit2));
        assert!(!tweaked_pk.verify_ecdsa_commitment(&secp, &sig, &nonce, TEST_ALGO2, wit2));
    }
}
