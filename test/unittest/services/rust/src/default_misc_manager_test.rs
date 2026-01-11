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

use crate::common::constants::ErrorCode;
use crate::common::types::Udid;
use crate::impls::default_misc_manager::DefaultMiscManager;
use crate::log_i;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::misc_manager::MiscManager;
use crate::ut_registry_guard;

fn create_test_udid(id: u8) -> Udid {
    let mut bytes = [0u8; 64];
    bytes[0] = id;
    Udid(bytes)
}

fn create_test_key_pair() -> KeyPair {
    KeyPair {
        pub_key: vec![1u8, 2, 3, 4],
        pri_key: vec![5u8, 6, 7, 8],
    }
}

fn mock_set_crypto_engine_success() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_sha256().returning(|_| Ok(vec![0u8; 32]));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

#[test]
fn default_misc_manager_get_distribute_key_test_peer_greater() {
    let _guard = ut_registry_guard!();
    log_i!("default_misc_manager_get_distribute_key_test_peer_greater start");

    mock_set_crypto_engine_success();

    let manager = DefaultMiscManager::new();
    let local_udid = create_test_udid(1);
    let peer_udid = create_test_udid(2);

    let result = manager.get_distribute_key(local_udid, peer_udid);
    assert!(result.is_ok());
}

#[test]
fn default_misc_manager_get_distribute_key_test_local_greater() {
    let _guard = ut_registry_guard!();
    log_i!("default_misc_manager_get_distribute_key_test_local_greater start");

    mock_set_crypto_engine_success();

    let manager = DefaultMiscManager::new();
    let local_udid = create_test_udid(2);
    let peer_udid = create_test_udid(1);

    let result = manager.get_distribute_key(local_udid, peer_udid);
    assert!(result.is_ok());
}

#[test]
fn default_misc_manager_get_distribute_key_test_crypto_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_misc_manager_get_distribute_key_test_crypto_error start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_sha256().returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let manager = DefaultMiscManager::new();
    let local_udid = create_test_udid(1);
    let peer_udid = create_test_udid(2);

    let result = manager.get_distribute_key(local_udid, peer_udid);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_misc_manager_set_local_key_pair_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_misc_manager_set_local_key_pair_test_success start");

    let mut manager = DefaultMiscManager::new();
    let key_pair = create_test_key_pair();

    let result = manager.set_local_key_pair(key_pair.clone());
    assert!(result.is_ok());

    let retrieved = manager.get_local_key_pair();
    assert!(retrieved.is_ok());
    let retrieved_key = retrieved.unwrap();
    assert_eq!(retrieved_key.pub_key, key_pair.pub_key);
    assert_eq!(retrieved_key.pri_key, key_pair.pri_key);
}

#[test]
fn default_misc_manager_get_local_key_pair_test_not_set() {
    let _guard = ut_registry_guard!();
    log_i!("default_misc_manager_get_local_key_pair_test_not_set start");

    let manager = DefaultMiscManager::new();

    let result = manager.get_local_key_pair();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_misc_manager_set_fwk_pub_key_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_misc_manager_set_fwk_pub_key_test_success start");

    let mut manager = DefaultMiscManager::new();
    let pub_key = vec![1u8, 2, 3, 4, 5];

    let result = manager.set_fwk_pub_key(pub_key.clone());
    assert!(result.is_ok());

    let retrieved = manager.get_fwk_pub_key();
    assert!(retrieved.is_ok());
    assert_eq!(retrieved.unwrap(), pub_key);
}

#[test]
fn default_misc_manager_set_fwk_pub_key_test_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_misc_manager_set_fwk_pub_key_test_empty start");

    let mut manager = DefaultMiscManager::new();
    let pub_key = vec![];

    let result = manager.set_fwk_pub_key(pub_key);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_misc_manager_get_fwk_pub_key_test_not_set() {
    let _guard = ut_registry_guard!();
    log_i!("default_misc_manager_get_fwk_pub_key_test_not_set start");

    let manager = DefaultMiscManager::new();

    let result = manager.get_fwk_pub_key();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
