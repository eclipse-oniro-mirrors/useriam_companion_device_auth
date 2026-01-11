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
use crate::impls::openssl_crypto_engine::OpenSSLCryptoEngine;
use crate::log_i;
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngine, KeyPair};
use crate::ut_registry_guard;

#[test]
fn openssl_crypto_engine_generate_ed25519_key_pair_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_generate_ed25519_key_pair_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let result = engine.generate_ed25519_key_pair();

    assert!(result.is_ok());
    let key_pair = result.unwrap();
    assert_eq!(key_pair.pub_key.len(), 32);
    assert_eq!(key_pair.pri_key.len(), 32);
}

#[test]
fn openssl_crypto_engine_ed25519_sign_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_ed25519_sign_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair = engine.generate_ed25519_key_pair().unwrap();

    let result = engine.ed25519_sign(&key_pair.pri_key, &[1, 2, 3]);
    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_ed25519_verify_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_ed25519_verify_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair = engine.generate_ed25519_key_pair().unwrap();
    let data = &[1, 2, 3];

    let signature = engine.ed25519_sign(&key_pair.pri_key, data).unwrap();
    let result = engine.ed25519_verify(&key_pair.pub_key, data, &signature);

    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_ed25519_verify_test_wrong_signature() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_ed25519_verify_test_wrong_signature start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair = engine.generate_ed25519_key_pair().unwrap();

    let wrong_signature = vec![0u8; 64];
    let result = engine.ed25519_verify(&key_pair.pub_key, &[1, 2, 3], &wrong_signature);

    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_ed25519_verify_test_wrong_data() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_ed25519_verify_test_wrong_data start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair = engine.generate_ed25519_key_pair().unwrap();

    let signature = engine.ed25519_sign(&key_pair.pri_key, &[1, 2, 3]).unwrap();
    let result = engine.ed25519_verify(&key_pair.pub_key, &[4, 5, 6], &signature);

    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_ed25519_verify_test_empty_pub_key() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_ed25519_verify_test_empty_pub_key start");

    let engine = OpenSSLCryptoEngine::new();
    let empty_key = vec![];
    let signature = vec![0u8; 64];

    let result = engine.ed25519_verify(&empty_key, &[1, 2, 3], &signature);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_ed25519_verify_test_invalid_pub_key() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_ed25519_verify_test_invalid_pub_key start");

    let engine = OpenSSLCryptoEngine::new();
    let invalid_key = vec![0u8; 32];
    let signature = vec![0u8; 64];

    let result = engine.ed25519_verify(&invalid_key, &[1, 2, 3], &signature);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_hmac_sha256_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_hmac_sha256_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let key = b"test hmac key";
    let data = b"test data for hmac";

    let result = engine.hmac_sha256(key, data);
    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_sha256_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_sha256_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let data = b"test data for hashing";

    let result = engine.sha256(data);
    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_secure_random_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_secure_random_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let mut buffer = [0u8; 32];

    let result = engine.secure_random(&mut buffer);
    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_secure_random_with_check_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_secure_random_with_check_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let mut buffer = [0u8; 32];

    let checker = |buf: &[u8]| -> bool {
        buf.iter().any(|&b| b != 0)
    };

    let result = engine.secure_random_with_check(&mut buffer, Box::new(checker));
    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_secure_random_with_check_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_secure_random_with_check_test_fail start");

    let engine = OpenSSLCryptoEngine::new();
    let mut buffer = [0u8; 4];

    let checker = |_buf: &[u8]| -> bool {
        false
    };

    let result = engine.secure_random_with_check(&mut buffer, Box::new(checker));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_aes_gcm_encrypt_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_encrypt_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let plaintext = b"test plaintext data";
    let param = AesGcmParam {
        key: vec![0u8; 32],
        iv: [0u8; AES_GCM_IV_SIZE],
        aad: vec![0u8; 16],
    };

    let result = engine.aes_gcm_encrypt(plaintext, &param);
    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_aes_gcm_encrypt_test_invalid_key_length() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_encrypt_test_invalid_key_length start");

    let engine = OpenSSLCryptoEngine::new();
    let plaintext = b"test plaintext";
    let param = AesGcmParam {
        key: vec![0u8; 16],
        iv: [0u8; AES_GCM_IV_SIZE],
        aad: vec![0u8; 16],
    };

    let result = engine.aes_gcm_encrypt(plaintext, &param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn openssl_crypto_engine_aes_gcm_decrypt_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_decrypt_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let plaintext = b"test plaintext data";
    let param = AesGcmParam {
        key: vec![0u8; 32],
        iv: [0u8; AES_GCM_IV_SIZE],
        aad: vec![0u8; 16],
    };

    let gcm_result = engine.aes_gcm_encrypt(plaintext, &param).unwrap();
    let decrypted = engine.aes_gcm_decrypt(&param, &gcm_result);

    assert!(decrypted.is_ok());
    assert_eq!(decrypted.unwrap(), plaintext);
}

#[test]
fn openssl_crypto_engine_aes_gcm_decrypt_test_invalid_key_length() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_decrypt_test_invalid_key_length start");

    let engine = OpenSSLCryptoEngine::new();
    let param = AesGcmParam {
        key: vec![0u8; 16],
        iv: [0u8; AES_GCM_IV_SIZE],
        aad: vec![0u8; 16],
    };
    let gcm_result = AesGcmResult {
        ciphertext: vec![0u8; 32],
        authentication_tag: [0u8; 16],
    };

    let result = engine.aes_gcm_decrypt(&param, &gcm_result);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn openssl_crypto_engine_aes_gcm_decrypt_test_wrong_tag() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_decrypt_test_wrong_tag start");

    let engine = OpenSSLCryptoEngine::new();
    let plaintext = b"test plaintext";
    let param = AesGcmParam {
        key: vec![0u8; 32],
        iv: [0u8; AES_GCM_IV_SIZE],
        aad: vec![0u8; 16],
    };

    let mut gcm_result = engine.aes_gcm_encrypt(plaintext, &param).unwrap();
    gcm_result.authentication_tag = [0xFFu8; 16];

    let result = engine.aes_gcm_decrypt(&param, &gcm_result);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_aes_gcm_decrypt_test_wrong_key() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_decrypt_test_wrong_key start");

    let engine = OpenSSLCryptoEngine::new();
    let plaintext = b"test plaintext";
    let param = AesGcmParam {
        key: vec![0u8; 32],
        iv: [0u8; AES_GCM_IV_SIZE],
        aad: vec![0u8; 16],
    };

    let gcm_result = engine.aes_gcm_encrypt(plaintext, &param).unwrap();

    let wrong_param = AesGcmParam {
        key: vec![1u8; 32],
        iv: [0u8; AES_GCM_IV_SIZE],
        aad: vec![0u8; 16],
    };

    let result = engine.aes_gcm_decrypt(&wrong_param, &gcm_result);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_hkdf_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_hkdf_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let salt = b"test salt";
    let key = b"test input key material";

    let result = engine.hkdf(salt, key);

    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_generate_x25519_key_pair_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_generate_x25519_key_pair_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let result = engine.generate_x25519_key_pair();

    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_x25519_ecdh_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_x25519_ecdh_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair1 = engine.generate_x25519_key_pair().unwrap();
    let key_pair2 = engine.generate_x25519_key_pair().unwrap();

    let shared_secret1 = engine.x25519_ecdh(&key_pair1, &key_pair2.pub_key);
    let shared_secret2 = engine.x25519_ecdh(&key_pair2, &key_pair1.pub_key);

    assert!(shared_secret1.is_ok());
    assert!(shared_secret2.is_ok());
    assert_eq!(shared_secret1.unwrap(), shared_secret2.unwrap());
}

#[test]
fn openssl_crypto_engine_x25519_ecdh_test_wrong_key_length() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_x25519_ecdh_test_wrong_key_length start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair = engine.generate_x25519_key_pair().unwrap();
    let wrong_pub_key = vec![0u8; 16];

    let result = engine.x25519_ecdh(&key_pair, &wrong_pub_key);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
