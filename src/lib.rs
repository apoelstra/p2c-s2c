// SPDX-License-Identifier: LGPL-3.0-or-later

//! Pay-to-Contract Sign-to-Contract

mod hashes;

pub use hashes::{Pay2ContractHash, Sign2ContractHash, TweakHash as _};

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
        Self {
            seckey: untweaked_key.add_tweak(&tweak_sc).expect("cryptographically unreachable"),
            pubkey: untweaked_pubkey.add_exp_tweak(&secp, &tweak_sc).expect("cryptographically unreachable"),
        }
    }

    pub fn public_key(&self) -> TweakedPublicKey {
        TweakedPublicKey {
            inner: self.pubkey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ALGO: &str = "TestAlgorithm/v001";
    
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

        // Tweaked signature
    }
}
