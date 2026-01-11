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
use crate::entry::companion_device_auth_ffi::{
    DataArray1024Ffi, HostBeginCompanionCheckInputFfi, HostEndCompanionCheckInputFfi,
    Uint16Array64Ffi,
};
use crate::log_i;
use crate::request::jobs::common_message::SecCommonReply;
use crate::request::status_sync::host_sync_status::HostDeviceSyncStatusRequest;
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, MockCryptoEngine};
use crate::traits::db_manager::{CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk,
    DeviceKey, UserInfo};
use crate::traits::host_db_manager::{HostDbManagerRegistry, MockHostDbManager};
use crate::traits::host_request_manager::{HostRequest, HostRequestInput};
use crate::ut_registry_guard;
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_valid_sync_reply_message(challenge: u64, protocol_list: &[u16], capability_list: &[u16]) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_u64(AttributeKey::AttrChallenge, challenge);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrProtocolList, protocol_list);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrCapabilityList, capability_list);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let reply = SecCommonReply { tag, iv, encrypt_data };
    reply.encode(DeviceType::None).unwrap()
}

fn create_mock_companion_device_info() -> CompanionDeviceInfo {
    CompanionDeviceInfo {
        template_id: 123,
        device_key: DeviceKey {
            device_id: String::from("test_device"),
            device_id_type: 1,
            user_id: 100,
        },
        user_info: UserInfo { user_id: 100, user_type: 0 },
        added_time: 123456,
        secure_protocol_id: 1,
        is_valid: true,
    }
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_host_db_manager() {
    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_read_device_capability_info().returning(|| {
        Ok(vec![CompanionDeviceCapability {
            device_type: DeviceType::None,
            esl: ExecutorSecurityLevel::Esl3,
            track_ability_level: 1,
        }])
    });
    mock_host_db_manager.expect_read_device_sk().returning(|| Ok(vec![CompanionDeviceSk {
        device_type: DeviceType::None,
        sk: Vec::new(),
    }]));
    mock_host_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device_info()));
    mock_host_db_manager.expect_update_device().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
}

#[test]
fn host_sync_status_request_new_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_new_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let result = HostDeviceSyncStatusRequest::new(&input);
    assert!(result.is_ok());

    let request = result.unwrap();
    assert_eq!(request.get_request_id(), 1);
    assert_eq!(request.capability_list, SUPPORT_CAPABILITY.to_vec());
}

#[test]
fn host_sync_status_request_new_test_secure_random_salt_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_new_test_secure_random_salt_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let result = HostDeviceSyncStatusRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_sync_status_request_prepare_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_prepare_test_not_implemented start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let result = request.prepare(HostRequestInput::SyncStatusBegin(input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_sync_status_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_begin_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let wrong_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let result = request.begin(HostRequestInput::SyncStatusEnd(wrong_input));
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_sync_status_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let result = request.end(HostRequestInput::SyncStatusBegin(input));
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_sync_status_request_end_test_protocal_list_convert_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_protocal_list_convert_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let mut protocal_list = Uint16Array64Ffi::default();
    protocal_list.len = 65;

    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list,
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_sync_status_request_end_test_capability_list_convert_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_capability_list_convert_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let mut capability_list = Uint16Array64Ffi::default();
    capability_list.len = 65;

    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_sync_status_request_end_test_read_device_capability_info_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_read_device_capability_info_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_read_device_capability_info().returning(|| Err(ErrorCode::NotFound));
    mock_host_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device_info()));
    mock_host_db_manager.expect_update_device().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert!(result.is_ok());
}

#[test]
fn host_sync_status_request_end_test_decode_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_decode_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_read_device_capability_info().returning(|| {
        Ok(vec![CompanionDeviceCapability {
            device_type: DeviceType::None,
            esl: ExecutorSecurityLevel::Esl3,
            track_ability_level: 1,
        }])
    });
    mock_host_db_manager.expect_get_device().returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_sync_status_request_end_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_get_session_key_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_read_device_capability_info().returning(|| {
        Ok(vec![CompanionDeviceCapability {
            device_type: DeviceType::None,
            esl: ExecutorSecurityLevel::Esl3,
            track_ability_level: 1,
        }])
    });
    mock_host_db_manager.expect_read_device_sk().returning(|| Err(ErrorCode::NotFound));
    mock_host_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device_info()));
    mock_host_db_manager.expect_update_device().returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let sec_message = create_valid_sync_reply_message(0, PROTOCAL_VERSION, SUPPORT_CAPABILITY);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_sync_status_request_end_test_decrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_decrypt_sec_message_fail start");

    mock_set_host_db_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let sec_message = create_valid_sync_reply_message(0, PROTOCAL_VERSION, SUPPORT_CAPABILITY);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert!(result.is_ok());
}

#[test]
fn host_sync_status_request_end_test_attribute_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_attribute_try_from_bytes_fail start");

    mock_set_host_db_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let sec_message = create_valid_sync_reply_message(0, PROTOCAL_VERSION, SUPPORT_CAPABILITY);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert!(result.is_ok());
}

#[test]
fn host_sync_status_request_end_test_challenge_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_challenge_mismatch start");

    mock_set_crypto_engine();
    mock_set_host_db_manager();

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.challenge = 999;

    let sec_message = create_valid_sync_reply_message(0, PROTOCAL_VERSION, SUPPORT_CAPABILITY);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert!(result.is_ok());
}

#[test]
fn host_sync_status_request_end_test_protocol_list_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_protocol_list_mismatch start");

    mock_set_crypto_engine();
    mock_set_host_db_manager();

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.challenge = 0;

    let mut protocal_list = Uint16Array64Ffi::default();
    protocal_list.data[0] = PROTOCAL_VERSION[0];
    protocal_list.len = 1;

    let wrong_protocol = vec![0xFFFF];
    let sec_message = create_valid_sync_reply_message(0, &wrong_protocol, SUPPORT_CAPABILITY);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list,
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert!(result.is_ok());
}

#[test]
fn host_sync_status_request_end_test_capability_list_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_capability_list_mismatch start");

    mock_set_crypto_engine();
    mock_set_host_db_manager();

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.challenge = 0;

    let mut protocal_list = Uint16Array64Ffi::default();
    protocal_list.data[0] = PROTOCAL_VERSION[0];
    protocal_list.len = 1;

    let mut capability_list = Uint16Array64Ffi::default();
    capability_list.data[0] = SUPPORT_CAPABILITY[0];
    capability_list.len = 1;

    let wrong_capability = vec![0xFFFF];
    let sec_message = create_valid_sync_reply_message(0, PROTOCAL_VERSION, &wrong_capability);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list,
        capability_list,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert!(result.is_ok());
}

#[test]
fn host_sync_status_request_end_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_success start");

    mock_set_crypto_engine();
    mock_set_host_db_manager();

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.challenge = 0;

    let mut protocal_list = Uint16Array64Ffi::default();
    protocal_list.data[0] = PROTOCAL_VERSION[0];
    protocal_list.len = 1;

    let mut capability_list = Uint16Array64Ffi::default();
    capability_list.data[0] = SUPPORT_CAPABILITY[0];
    capability_list.data[1] = SUPPORT_CAPABILITY[1];
    capability_list.len = 2;

    let sec_message = create_valid_sync_reply_message(0, PROTOCAL_VERSION, SUPPORT_CAPABILITY);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list,
        capability_list,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(HostRequestInput::SyncStatusEnd(end_input));
    assert!(result.is_ok());
}
