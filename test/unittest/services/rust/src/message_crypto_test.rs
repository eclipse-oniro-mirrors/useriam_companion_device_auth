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
const FILE_ID: u16 = TestFileId::MessageCryptoTest as u16;

use crate::common::constants::*;
use crate::jobs::message_crypto::{
    decrypt_sec_message, derive_session_key, encrypt_sec_message, generate_key_pair,
    get_distribute_key, key_agreement, compute_mac,
};
use crate::log_i;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::ut_registry_guard;

#[test]
fn decrypt_sec_message_test_tag_len_error() {
    let _guard = ut_registry_guard!();
    log_i!("decrypt_sec_message_test_tag_len_error start");

    let result = decrypt_sec_message(1, &[], &[], &[], &[]);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn decrypt_sec_message_test_iv_len_error() {
    let _guard = ut_registry_guard!();
    log_i!("decrypt_sec_message_test_iv_len_error start");

    let result = decrypt_sec_message(1, &[], &[], &[0u8; AES_GCM_TAG_SIZE], &[]);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn get_distribute_key_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("get_distribute_key_test_success start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_distribute_key().returning(|| Ok(Vec::new()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let local_device_id = "a".repeat(64);
    let peer_device_id = "b".repeat(64);

    let result = get_distribute_key(&local_device_id, &peer_device_id);
    assert!(result.is_ok());
}

#[test]
fn get_distribute_key_test_local_device_id_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("get_distribute_key_test_local_device_id_try_into_fail start");

    let local_device_id = "a".repeat(1);
    let peer_device_id = "b".repeat(64);

    let result = get_distribute_key(&local_device_id, &peer_device_id);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn get_distribute_key_test_peer_device_id_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("get_distribute_key_test_peer_device_id_try_into_fail start");

    let local_device_id = "a".repeat(64);
    let peer_device_id = "b".repeat(1);

    let result = get_distribute_key(&local_device_id, &peer_device_id);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn generate_key_pair_test_unsupported_algorithm() {
    let _guard = ut_registry_guard!();
    log_i!("generate_key_pair_test_unsupported_algorithm start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| panic!("unsupported algorithm must be rejected before dispatch"));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    assert_eq!(generate_key_pair(0), Err(ErrorCode::BadParam));
    assert_eq!(generate_key_pair(2), Err(ErrorCode::BadParam));
}

#[test]
fn key_agreement_test_unsupported_algorithm() {
    let _guard = ut_registry_guard!();
    log_i!("key_agreement_test_unsupported_algorithm start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_x25519_ecdh()
        .returning(|| panic!("unsupported algorithm must be rejected before dispatch"));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let key_pair = KeyPair::new(Vec::new(), Vec::new());
    assert_eq!(key_agreement(0, &key_pair, &[]), Err(ErrorCode::BadParam));
}

#[test]
fn symmetric_dispatch_test_invalid_algorithm_rejected() {
    let _guard = ut_registry_guard!();
    log_i!("symmetric_dispatch_test_invalid_algorithm_rejected start");

    CryptoEngineRegistry::set(Box::new(MockCryptoEngine::new()));

    assert_eq!(derive_session_key(0, &[], &[]), Err(ErrorCode::BadParam));
    assert_eq!(derive_session_key(2, &[], &[]), Err(ErrorCode::BadParam));
    assert_eq!(encrypt_sec_message(0, &[], &[]), Err(ErrorCode::BadParam));
    assert_eq!(
        decrypt_sec_message(0, &[], &[], &[], &[]),
        Err(ErrorCode::BadParam)
    );
    assert_eq!(compute_mac(0, &[], &[]), Err(ErrorCode::BadParam));
}
