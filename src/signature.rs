// SPDX-License-Identifier: LGPL-3.0-or-later

//! Sign-to-Contract signatures

use core::ffi::{c_int, c_uchar, c_uint, c_void};

use secp256k1::{Keypair, PublicKey};
use secp256k1::ffi::{secp256k1_nonce_function_bip340, secp256k1_nonce_function_rfc6979};

use crate::hashes::TweakHash;
use crate::{Full, TweakedKey, XOnly};

// See https://github.com/rust-lang/rust/issues/88345
#[allow(non_camel_case_types)]
type size_t = usize;

pub struct NonceFnData<'s, C: secp256k1::Context> {
    pub ctx: &'s secp256k1::Secp256k1<C>,
    pub data: &'s [u8],
    pub original_nonce: Option<secp256k1::PublicKey>,
}

// SAFETY:
//   * The *32 arguments must be pointers to 32-byte array.
//   * The `algo16` argument must be a pointer to a 16-byte array.
//   * The `data` argument must be a pointer to a `NonceFnData`
pub unsafe extern "C" fn s2c_ecdsa_nonce_fn<C: secp256k1::Signing + secp256k1::Verification, H: TweakHash<AllowedKeys = Full>>(
    nonce32: *mut c_uchar,
    msg32: *const c_uchar,
    key32: *const c_uchar,
    algo16: *const c_uchar,
    data: *mut c_void,
    attempt: c_uint,
) -> c_int {
    // 1. First compute original nonce using RFC6979. (This is not a visible
    //    choice and we can change it later without breaking verifiers.)
    let default_fn = secp256k1_nonce_function_rfc6979.unwrap(); // unwrap is because secp-sys API is dumb
    if default_fn(nonce32, msg32, key32, algo16, data, attempt) == 0 {
        return 0;
    }
    let data = data
        .cast::<NonceFnData<'_, C>>()
        .as_mut()
        .expect("required by SAFETY comment");

    // 2. The returned nonce is a secret nonce. Interpret it as a secret key
    //    and tweak it.
    let nonce32 = nonce32
        .cast::<[u8; 32]>()
        .as_mut()
        .expect("required by SAFETY comment");
    let Ok(sk) = secp256k1::SecretKey::from_byte_array(*nonce32) else {
        return 0;
    };
    let untweaked_pk = PublicKey::from_secret_key(data.ctx, &sk);
    let tweaked_keypair = TweakedKey::<_, H>::new(&(sk, untweaked_pk), data.data);

    // 3. Put the tweaked nonce in the outptr, and untweaked nonce in the data carrier.
    nonce32.copy_from_slice(&tweaked_keypair.as_inner().0.secret_bytes());
    data.original_nonce = Some(untweaked_pk);

    1 // return success
}

pub unsafe extern "C" fn s2c_schnorr_nonce_fn<C: secp256k1::Signing + secp256k1::Verification, H: TweakHash<AllowedKeys = XOnly>>(
    nonce32: *mut c_uchar,
    msg32: *const c_uchar,
    msg_len: size_t,
    key32: *const c_uchar,
    xonly_pk32: *const c_uchar,
    algo16: *const c_uchar,
    algo_len: size_t,
    data: *mut c_void,
) -> c_int {
    // 1. First compute original nonce using default nonce function. (This is not a visible
    //    choice and we can change it later without breaking verifiers.)
    let default_fn = secp256k1_nonce_function_bip340.unwrap(); // unwrap is because secp-sys API is dumb
    if default_fn(
        nonce32, msg32, msg_len, key32, xonly_pk32, algo16, algo_len, data,
    ) == 0
    {
        return 0;
    }
    let data = data
        .cast::<NonceFnData<'_, C>>()
        .as_mut()
        .expect("required by SAFETY comment");

    // 2. The returned nonce is a secret nonce. Interpret it as a secret key
    //    and tweak it.
    let nonce32 = nonce32
        .cast::<[u8; 32]>()
        .as_mut()
        .expect("required by SAFETY comment");
    let Ok(sk) = secp256k1::SecretKey::from_byte_array(*nonce32) else {
        return 0;
    };
    let untweaked_keypair = Keypair::from_secret_key(data.ctx, &sk);
    let tweaked_keypair = TweakedKey::<_, H>::new(&untweaked_keypair, data.data);

    // 3. Put the tweaked nonce in the outptr, and untweaked nonce in the data carrier.
    nonce32.copy_from_slice(&tweaked_keypair.as_inner().secret_bytes());

    // FIXME make original_nonce be a K
    data.original_nonce = Some(untweaked_keypair.public_key());

    1 // return success
}
