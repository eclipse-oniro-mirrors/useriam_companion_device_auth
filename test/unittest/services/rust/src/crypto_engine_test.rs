/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::common::constants::*;
use crate::log_i;
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngine, DummyCryptoEngine, KeyPair};
use crate::ut_registry_guard;

#[test]
fn dummy_crypto_engine_test() {
    let _guard = ut_registry_guard!();
    log_i!("dummy_crypto_engine_test start");

    let dummy_crypto_engine = DummyCryptoEngine;
    let aes_gcm_param = AesGcmParam { key: Vec::<u8>::new(), iv: [0u8; AES_GCM_IV_SIZE], aad: Vec::<u8>::new() };

    assert_eq!(dummy_crypto_engine.generate_ed25519_key_pair(), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_crypto_engine.ed25519_sign(&[], &[]), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_crypto_engine.ed25519_verify(&[], &[], &[]), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_crypto_engine.hmac_sha256(&[], &[]), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_crypto_engine.sha256(&[]), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_crypto_engine.secure_random(&mut []), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_crypto_engine.secure_random_with_check(&mut [], Box::new(|_| true)), Err(ErrorCode::GeneralError));
    assert!(dummy_crypto_engine.aes_gcm_encrypt(&[], &aes_gcm_param).is_err());
    assert_eq!(
        dummy_crypto_engine.aes_gcm_decrypt(
            &aes_gcm_param,
            &AesGcmResult { ciphertext: Vec::<u8>::new(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] }
        ),
        Err(ErrorCode::GeneralError)
    );
    assert_eq!(dummy_crypto_engine.hkdf(&[], &[]), Err(ErrorCode::GeneralError));
    assert_eq!(
        dummy_crypto_engine.p256_ecdh(&KeyPair::new(Vec::<u8>::new(), Vec::<u8>::new()), &[]),
        Err(ErrorCode::GeneralError)
    );
    assert_eq!(
        dummy_crypto_engine.x25519_ecdh(&KeyPair::new(Vec::<u8>::new(), Vec::<u8>::new()), &[]),
        Err(ErrorCode::GeneralError)
    );
    assert_eq!(dummy_crypto_engine.generate_x25519_key_pair(), Err(ErrorCode::GeneralError));
}

#[test]
fn key_pair_test() {
    let _guard = ut_registry_guard!();
    log_i!("key_pair_test start");

    let mut key_pair = KeyPair { pub_key: Vec::new(), pri_key: Vec::new() };

    assert_eq!(key_pair.check_valid(), false);

    key_pair.pub_key = vec![1, 2, 3];
    assert_eq!(key_pair.check_valid(), false);

    key_pair.pri_key = vec![4, 5, 6];
    assert_eq!(key_pair.check_valid(), true);
}
