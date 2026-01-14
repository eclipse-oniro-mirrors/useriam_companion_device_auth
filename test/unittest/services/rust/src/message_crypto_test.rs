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
use crate::common::types::*;
use crate::jobs::message_crypto::{decrypt_sec_message, get_distribute_key};
use crate::log_i;
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::ut_registry_guard;

#[test]
fn decrypt_sec_message_test_tag_len_error() {
    let _guard = ut_registry_guard!();
    log_i!("decrypt_sec_message_test_tag_len_error start");

    let result = decrypt_sec_message(&[], &[], &[], &[]);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn decrypt_sec_message_test_iv_len_error() {
    let _guard = ut_registry_guard!();
    log_i!("decrypt_sec_message_test_iv_len_error start");

    let result = decrypt_sec_message(&[], &[], &[0u8; AES_GCM_TAG_SIZE], &[]);
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
