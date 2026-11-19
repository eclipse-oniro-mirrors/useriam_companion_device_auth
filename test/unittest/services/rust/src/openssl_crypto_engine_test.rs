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

use crate::traits::log_trace::TestFileId;
const FILE_ID: u16 = TestFileId::OpensslCryptoEngineTest as u16;

use crate::common::constants::*;
use crate::impls::openssl_crypto_engine::OpenSSLCryptoEngine;
use crate::log_i;
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngine};
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
fn openssl_crypto_engine_aes_gcm_encrypt_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_encrypt_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let plaintext = b"test plaintext data";
    let param = AesGcmParam { key: vec![0u8; 32], iv: [0u8; AES_GCM_IV_SIZE], aad: vec![0u8; 16] };

    let result = engine.aes_gcm_encrypt(plaintext, &param);
    assert!(result.is_ok());
}

#[test]
fn openssl_crypto_engine_aes_gcm_encrypt_test_invalid_key_length() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_encrypt_test_invalid_key_length start");

    let engine = OpenSSLCryptoEngine::new();
    let plaintext = b"test plaintext";
    let param = AesGcmParam { key: vec![0u8; 16], iv: [0u8; AES_GCM_IV_SIZE], aad: vec![0u8; 16] };

    let result = engine.aes_gcm_encrypt(plaintext, &param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn openssl_crypto_engine_aes_gcm_decrypt_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_decrypt_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let plaintext = b"test plaintext data";
    let param = AesGcmParam { key: vec![0u8; 32], iv: [0u8; AES_GCM_IV_SIZE], aad: vec![0u8; 16] };

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
    let param = AesGcmParam { key: vec![0u8; 16], iv: [0u8; AES_GCM_IV_SIZE], aad: vec![0u8; 16] };
    let gcm_result = AesGcmResult { ciphertext: vec![0u8; 32], authentication_tag: [0u8; 16] };

    let result = engine.aes_gcm_decrypt(&param, &gcm_result);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn openssl_crypto_engine_aes_gcm_decrypt_test_wrong_tag() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_aes_gcm_decrypt_test_wrong_tag start");

    let engine = OpenSSLCryptoEngine::new();
    let plaintext = b"test plaintext";
    let param = AesGcmParam { key: vec![0u8; 32], iv: [0u8; AES_GCM_IV_SIZE], aad: vec![0u8; 16] };

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
    let param = AesGcmParam { key: vec![0u8; 32], iv: [0u8; AES_GCM_IV_SIZE], aad: vec![0u8; 16] };

    let gcm_result = engine.aes_gcm_encrypt(plaintext, &param).unwrap();

    let wrong_param = AesGcmParam { key: vec![1u8; 32], iv: [0u8; AES_GCM_IV_SIZE], aad: vec![0u8; 16] };

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

#[test]
fn openssl_crypto_engine_generate_p256_key_pair_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_generate_p256_key_pair_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    // repeat: a scalar with a leading zero byte must still yield a 32B left-padded key
    for _ in 0..20 {
        let result = engine.generate_p256_key_pair();
        assert!(result.is_ok());
        let key_pair = result.unwrap();
        assert_eq!(key_pair.pub_key.len(), BINDING_SIGNATURE_PUB_KEY_LEN);
        assert_eq!(key_pair.pub_key.first(), Some(&0x04));
        assert_eq!(key_pair.pri_key.len(), BINDING_SIGNATURE_PRI_KEY_LEN);
    }
}

#[test]
fn openssl_crypto_engine_generate_p256_key_pair_test_unique() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_generate_p256_key_pair_test_unique start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair1 = engine.generate_p256_key_pair().unwrap();
    let key_pair2 = engine.generate_p256_key_pair().unwrap();
    assert_ne!(key_pair1.pri_key, key_pair2.pri_key);
    assert_ne!(key_pair1.pub_key, key_pair2.pub_key);
}

#[test]
fn openssl_crypto_engine_p256_ecdsa_sign_verify_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_p256_ecdsa_sign_verify_test_success start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair = engine.generate_p256_key_pair().unwrap();
    let data = b"binding-signature challenge sample bytes";

    let sign_result = engine.p256_ecdsa_sign(&key_pair.pri_key, data);
    assert!(sign_result.is_ok());
    let signature = sign_result.unwrap();
    // Signature is variable length within the P-256 bound
    assert!(!signature.is_empty());
    assert!(signature.len() <= BINDING_SIGNATURE_P256_DER_MAX_LEN);

    let verify_result = engine.p256_ecdsa_verify(&key_pair.pub_key, data, &signature);
    assert!(verify_result.is_ok());
}

#[test]
fn openssl_crypto_engine_p256_ecdsa_sign_test_wrong_key_length() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_p256_ecdsa_sign_test_wrong_key_length start");

    let engine = OpenSSLCryptoEngine::new();
    let result = engine.p256_ecdsa_sign(&[1u8; 31], &[1, 2, 3]);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn openssl_crypto_engine_p256_ecdsa_verify_test_wrong_key() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_p256_ecdsa_verify_test_wrong_key start");

    let engine = OpenSSLCryptoEngine::new();
    let signer = engine.generate_p256_key_pair().unwrap();
    let other = engine.generate_p256_key_pair().unwrap();
    let data = b"payload";
    let signature = engine.p256_ecdsa_sign(&signer.pri_key, data).unwrap();

    // verified by the signer's key, rejected under another binding's key
    assert!(engine.p256_ecdsa_verify(&signer.pub_key, data, &signature).is_ok());
    assert_eq!(engine.p256_ecdsa_verify(&other.pub_key, data, &signature), Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_p256_ecdsa_verify_test_tampered() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_p256_ecdsa_verify_test_tampered start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair = engine.generate_p256_key_pair().unwrap();
    let data = b"payload";
    let mut signature = engine.p256_ecdsa_sign(&key_pair.pri_key, data).unwrap();

    // tampered message fails
    assert_eq!(
        engine.p256_ecdsa_verify(&key_pair.pub_key, b"payload2", &signature),
        Err(ErrorCode::GeneralError)
    );

    // tampered signature body fails
    let last = signature.len() - 1;
    signature[last] ^= 0x01;
    assert_eq!(engine.p256_ecdsa_verify(&key_pair.pub_key, data, &signature), Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_p256_ecdsa_verify_test_malformed_der() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_p256_ecdsa_verify_test_malformed_der start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair = engine.generate_p256_key_pair().unwrap();
    let data = b"payload";
    let signature = engine.p256_ecdsa_sign(&key_pair.pri_key, data).unwrap();

    // trailing byte after a valid signature fails (re-encode mismatch)
    let mut trailing = signature.clone();
    trailing.push(0x00);
    assert_eq!(engine.p256_ecdsa_verify(&key_pair.pub_key, data, &trailing), Err(ErrorCode::GeneralError));

    // empty and over-bound signatures are rejected before the engine parse
    assert_eq!(engine.p256_ecdsa_verify(&key_pair.pub_key, data, &[]), Err(ErrorCode::GeneralError));
    let too_long = vec![0x30u8; BINDING_SIGNATURE_VALUE_MAX_LEN + 1];
    assert_eq!(engine.p256_ecdsa_verify(&key_pair.pub_key, data, &too_long), Err(ErrorCode::GeneralError));

    // a wrong first byte (not 0x04) in the 65B public key is rejected
    let mut bad_pub = key_pair.pub_key.clone();
    bad_pub[0] = 0x07;
    assert_eq!(engine.p256_ecdsa_verify(&bad_pub, data, &signature), Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_p256_check_pub_key_test_off_curve_point() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_p256_check_pub_key_test_off_curve_point start");

    let engine = OpenSSLCryptoEngine::new();
    let key_pair = engine.generate_p256_key_pair().unwrap();
    assert!(engine.p256_check_pub_key(&key_pair.pub_key).is_ok());

    // well-formed SEC1 layout but (x, y) = (1, 1) is not on P-256
    let mut off_curve = vec![0u8; BINDING_SIGNATURE_PUB_KEY_LEN];
    off_curve[0] = 0x04;
    off_curve[31] = 0x01;
    off_curve[63] = 0x01;
    assert_eq!(engine.p256_check_pub_key(&off_curve), Err(ErrorCode::GeneralError));
}

#[test]
fn openssl_crypto_engine_p256_ecdsa_sign_test_zero_scalar() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_p256_ecdsa_sign_test_zero_scalar start");

    let engine = OpenSSLCryptoEngine::new();
    assert_eq!(
        engine.p256_ecdsa_sign(&[0u8; BINDING_SIGNATURE_PRI_KEY_LEN], &[1, 2, 3]),
        Err(ErrorCode::BadParam)
    );
}

#[test]
fn openssl_crypto_engine_p256_ecdsa_sign_test_scalar_out_of_range() {
    let _guard = ut_registry_guard!();
    log_i!("openssl_crypto_engine_p256_ecdsa_sign_test_scalar_out_of_range start");

    const P256_ORDER_N: [u8; BINDING_SIGNATURE_PRI_KEY_LEN] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    let engine = OpenSSLCryptoEngine::new();
    // d = n is rejected
    assert_eq!(engine.p256_ecdsa_sign(&P256_ORDER_N, &[1, 2, 3]), Err(ErrorCode::BadParam));

    // d = n - 1 stays a valid scalar
    let mut order_minus_one = P256_ORDER_N;
    order_minus_one[31] -= 1;
    assert!(engine.p256_ecdsa_sign(&order_minus_one, &[1, 2, 3]).is_ok());
}
