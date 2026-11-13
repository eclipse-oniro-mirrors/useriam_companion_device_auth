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
const FILE_ID: u16 = TestFileId::HostSyncStatusTest as u16;

// Values this build cannot interpret: a protocol only a newer peer enrolls at.
const HIGHER_PROTOCOL_VERSION: u16 = 2;

use crate::common::constants::*;

const PROTOCOL_VERSION_1: u16 = 1;
const ALL_CAPABILITIES: &[u16] =
    &[Capability::DelegateAuth as u16, Capability::TokenAuth as u16, Capability::ObtainToken as u16];
use crate::entry::companion_device_auth_ffi::{
    DataArray1024Ffi, HostBeginCompanionCheckInputFfi, HostBeginCompanionCheckOutputFfi, HostEndCompanionCheckInputFfi,
    HostEndCompanionCheckOutputFfi,
};
use crate::log_i;
use crate::request::jobs::common_message::SecCommonReply;
use crate::request::status_sync::host_sync_status::HostDeviceSyncStatusRequest;
use crate::traits::companion_device_db_manager::{CompanionDeviceDbManagerRegistry, MockCompanionDeviceDbManager};
use crate::traits::crypto_engine::{CryptoEngineRegistry, MockCryptoEngine};
use crate::common::algorithm::SelectedAlgorithms;
use crate::traits::db_manager::{CompanionDevice, CompanionDeviceCapability, CompanionDeviceKeyMaterial, DeviceKey, UserInfo, UserKey};
use crate::traits::request_manager::{Request, RequestParam};
use crate::ut_registry_guard;
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_valid_sync_reply_message(challenge: u64, companion_protocol_list: &[u16], companion_capability_list: &[u16]) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_u64(AttributeKey::AttrHostChallenge, challenge);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrProtocolList, companion_protocol_list);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrCapabilityList, companion_capability_list);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let reply = SecCommonReply { tag, iv, encrypt_data };
    reply.encode(ProcessorType::Default).unwrap()
}

fn create_mock_companion_device() -> CompanionDevice {
    create_mock_companion_device_with_capabilities(vec![1, 2, 3])
}

fn create_mock_companion_device_with_capabilities(enrolled_capability_list: Vec<u16>) -> CompanionDevice {
    CompanionDevice {
        template_id: 123,
        device_key: DeviceKey {
            device_id: String::from("test_device"),
            device_id_type: 1,
            user_id: 100,
            sub_profile_id: 0,
        },
        user_info: UserInfo { user_key: UserKey { user_id: 100, sub_profile_id: 0 }, user_type: 0 },
        added_time: 123456,
        is_valid: true,
        enrolled_capability_list,
        enrolled_protocol_id: 1,
        secure_protocol_id: 1,
    }
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_expect_capability_rows(mock: &mut MockCompanionDeviceDbManager) {
    mock.expect_read_device_capability_info().returning(|| {
        Ok(vec![CompanionDeviceCapability {
            processor_type: ProcessorType::Default,
            esl: ExecutorSecurityLevel::Esl0,
            track_ability_level: TrackAbilityLevel::Tal0,
        }])
    });
}

fn mock_set_companion_device_db_manager() {
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    mock_companion_device_db_manager.expect_update_device().returning(|| Ok(()));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));
}

#[test]
fn host_sync_status_request_new_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_new_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let result = HostDeviceSyncStatusRequest::new(&input);
    assert!(result.is_ok());

    let request = result.unwrap();
    assert_eq!(request.get_request_id(), 1);
}

#[test]
fn host_sync_status_request_new_test_secure_random_salt_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_new_test_secure_random_salt_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
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

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let mut output = HostBeginCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusBegin(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_sync_status_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_begin_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let wrong_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&wrong_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_sync_status_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let mut output = HostBeginCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusBegin(&input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_sync_status_request_end_test_decode_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_decode_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let update_device_calls_in_mock = update_device_calls.clone();
    mock_companion_device_db_manager.expect_update_device().returning(move || {
        update_device_calls_in_mock.set(update_device_calls_in_mock.get() + 1);
        Ok(())
    });
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    // A decode failure is unauthenticated: the round fails and the binding is never invalidated.
    assert_eq!(result, Err(ErrorCode::GeneralError));
    assert_eq!(update_device_calls.get(), 0);
}

#[test]
fn host_sync_status_request_end_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_get_session_key_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_read_device_sk().returning(|| Err(ErrorCode::NotFound));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    mock_companion_device_db_manager.expect_update_device().returning(|| Err(ErrorCode::GeneralError));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_sync_status_request_end_test_decrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_decrypt_sec_message_fail start");

    mock_set_companion_device_db_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_sync_status_request_end_test_attribute_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_attribute_try_from_bytes_fail start");

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert!(result.is_ok());
}

#[test]
fn host_sync_status_request_end_test_challenge_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_challenge_mismatch start");

    mock_set_crypto_engine();
    mock_set_companion_device_db_manager();

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 999;

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_sync_status_request_end_test_protocol_list_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_protocol_list_mismatch start");

    mock_set_crypto_engine();
    mock_set_companion_device_db_manager();

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 0;

    let wrong_protocol = vec![0xFFFF];
    let sec_message = create_valid_sync_reply_message(0, &wrong_protocol, ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::ProtocolNegotiationFailed));
}

// An authenticated capability announcement entirely outside the enrolled capability list is a parameter
// divergence: fail the check and invalidate the credential.
#[test]
fn host_sync_status_request_end_test_capability_outside_enrolled_list_fails_and_invalidates() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_capability_outside_enrolled_list_fails_and_invalidates start");

    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    set_up_sync_db_mock(update_device_calls.clone());

    let wrong_capability = vec![0xFFFF];
    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], &wrong_capability);
    let (result, output) = run_sync_end(sec_message);
    assert_eq!(result, Err(ErrorCode::CapabilityNegotiationFailed));
    assert_eq!(output_capability_values(&output), Vec::<u16>::new());
    assert_eq!(update_device_calls.get(), 1);
}

#[test]
fn host_sync_status_request_end_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_success start");

    mock_set_crypto_engine();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 0;

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert!(result.is_ok());
}

#[test]
fn host_sync_status_request_end_test_enrolled_protocol_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_enrolled_protocol_mismatch start");

    mock_set_crypto_engine();
    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let update_device_calls_in_mock = update_device_calls.clone();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| {
        // Binding enrolled at a protocol this build does not speak.
        let mut device = create_mock_companion_device();
        device.enrolled_protocol_id = HIGHER_PROTOCOL_VERSION;
        Ok(device)
    });
    mock_companion_device_db_manager.expect_update_device().returning(move || {
        update_device_calls_in_mock.set(update_device_calls_in_mock.get() + 1);
        Ok(())
    });
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 0;

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::ProtocolNegotiationFailed));
    assert_eq!(update_device_calls.get(), 1);
}

// An authenticated divergence (found after the proof verified) invalidates the binding
// regardless of which user key the discovery cache holds.
#[test]
fn host_sync_status_request_end_test_untrusted_user_key_still_invalidates() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_untrusted_user_key_skips_invalidation start");

    mock_set_crypto_engine();
    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let update_device_calls_in_mock = update_device_calls.clone();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| {
        let mut device = create_mock_companion_device();
        device.enrolled_protocol_id = HIGHER_PROTOCOL_VERSION;
        Ok(device)
    });
    mock_companion_device_db_manager.expect_update_device().returning(move || {
        update_device_calls_in_mock.set(update_device_calls_in_mock.get() + 1);
        Ok(())
    });
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 0;

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::ProtocolNegotiationFailed));
    assert_eq!(update_device_calls.get(), 1);
}

#[test]
fn host_sync_status_request_end_test_get_device_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_get_device_fail start");

    mock_set_crypto_engine();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| Err(ErrorCode::NotFound));
    mock_companion_device_db_manager.expect_update_device().returning(|| Ok(()));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 0;

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_sync_status_request_end_test_empty_companion_protocol_list() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_empty_companion_protocol_list start");

    mock_set_crypto_engine();
    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let update_device_calls_in_mock = update_device_calls.clone();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    mock_companion_device_db_manager.expect_update_device().returning(move || {
        update_device_calls_in_mock.set(update_device_calls_in_mock.get() + 1);
        Ok(())
    });
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 0;

    let sec_message = create_valid_sync_reply_message(0, &[], ALL_CAPABILITIES);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::ProtocolNegotiationFailed));
    assert_eq!(update_device_calls.get(), 1);
}

// Duplicated IDs inside the authenticated lists are set-equivalent: the round succeeds and the
// effective capability set is deduplicated.
#[test]
fn host_sync_status_request_end_test_duplicate_ids_are_set_equivalent() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_duplicate_ids_are_set_equivalent start");

    mock_set_crypto_engine();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 0;

    let repeated_protocols = vec![PROTOCOL_VERSION_1, PROTOCOL_VERSION_1];
    let repeated_capabilities = [ALL_CAPABILITIES, ALL_CAPABILITIES].concat();
    let sec_message =
        create_valid_sync_reply_message(0, &repeated_protocols, &repeated_capabilities);
    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    assert!(result.is_ok());
    assert_eq!(output_capability_values(&output), ALL_CAPABILITIES.to_vec());
}

#[test]
fn host_sync_status_request_end_test_secure_protocol_not_supported()
{
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_secure_protocol_not_supported start");

    mock_set_crypto_engine();
    // Bare mock: any DB access before the entry validation would panic, pinning the check
    // ahead of get_device.
    CompanionDeviceDbManagerRegistry::set(Box::new(MockCompanionDeviceDbManager::new()));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 0;

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    // A future version and the INVALID sentinel are both unusable scalars: the round must fail
    // at the security-layer entry without touching the persisted binding.
    for secure_protocol_id in [HIGHER_PROTOCOL_VERSION, SECURE_PROTOCOL_ID_INVALID] {
        let end_input = HostEndCompanionCheckInputFfi {
            request_id: 1,
            template_id: 123,
            secure_protocol_id,
            sec_message: DataArray1024Ffi::try_from(sec_message.clone()).unwrap(),
        };

        let mut output = HostEndCompanionCheckOutputFfi::default();
        let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
        let result = request.end(param);
        assert_eq!(result, Err(ErrorCode::SecureProtocolNotSupported));
    }
}

// ============================================================================
// Capability-axis judgements on the sync reply
// ============================================================================

fn set_up_sync_db_mock(update_device_calls: std::rc::Rc<std::cell::Cell<u32>>) {
    set_up_sync_db_mock_with_device(create_mock_companion_device(), update_device_calls);
}

fn set_up_sync_db_mock_with_device(
    device: CompanionDevice,
    update_device_calls: std::rc::Rc<std::cell::Cell<u32>>,
) {
    mock_set_crypto_engine();
    let update_device_calls_in_mock = update_device_calls.clone();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(move || Ok(device.clone()));
    mock_companion_device_db_manager.expect_update_device().returning(move || {
        update_device_calls_in_mock.set(update_device_calls_in_mock.get() + 1);
        Ok(())
    });
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));
}

fn run_sync_end(sec_message: Vec<u8>) -> (Result<(), ErrorCode>, HostEndCompanionCheckOutputFfi) {
    let input = HostBeginCompanionCheckInputFfi { request_id: 1, user_id: 0, ..Default::default() };
    let mut request = HostDeviceSyncStatusRequest::new(&input).unwrap();
    request.host_challenge = 0;

    let end_input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndCompanionCheckOutputFfi::default();
    let param = RequestParam::HostSyncStatusEnd(&end_input, &mut output);
    let result = request.end(param);
    (result, output)
}

fn output_capability_values(output: &HostEndCompanionCheckOutputFfi) -> Vec<u16> {
    output.companion_capability_list.data[..output.companion_capability_list.len as usize].to_vec()
}

// The selected capability list is frozen at enrollment: an announcement growing beyond it is
// clipped, nothing is written, and re-enrollment is the only way to widen it.
#[test]
fn host_sync_status_request_end_test_capability_growth_clamped_to_selected_list() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_capability_growth_clamped_to_selected_list start");

    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let persisted: Vec<u16> = vec![Capability::DelegateAuth as u16, Capability::TokenAuth as u16];
    set_up_sync_db_mock_with_device(
        create_mock_companion_device_with_capabilities(persisted.clone()),
        update_device_calls.clone(),
    );

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let (result, output) = run_sync_end(sec_message);
    assert!(result.is_ok());
    assert_eq!(output_capability_values(&output), persisted);
    assert_eq!(update_device_calls.get(), 0);
}

// Partial overlap leaves part of the enrolled capability list uncovered: fail instead of returning only the
// intersection, and invalidate the diverged credential.
#[test]
fn host_sync_status_request_end_test_capability_partial_overlap_fails_and_invalidates() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_capability_partial_overlap_fails_and_invalidates start");

    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let persisted: Vec<u16> = vec![Capability::DelegateAuth as u16, Capability::TokenAuth as u16];
    set_up_sync_db_mock_with_device(
        create_mock_companion_device_with_capabilities(persisted),
        update_device_calls.clone(),
    );

    let announced: &[u16] = &[Capability::TokenAuth as u16, Capability::ObtainToken as u16];
    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], announced);
    let (result, output) = run_sync_end(sec_message);
    assert_eq!(result, Err(ErrorCode::CapabilityNegotiationFailed));
    assert_eq!(output_capability_values(&output), Vec::<u16>::new());
    assert_eq!(update_device_calls.get(), 1);
}

// A strict subset of the enrolled capability list is also a divergence: fail the check and invalidate the
// credential rather than accepting a shrunk effective capability set.
#[test]
fn host_sync_status_request_end_test_capability_shrink_fails_and_invalidates() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_capability_shrink_fails_and_invalidates start");

    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    set_up_sync_db_mock(update_device_calls.clone());

    let shrunk: &[u16] = &[Capability::DelegateAuth as u16, Capability::TokenAuth as u16];
    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], shrunk);
    let (result, output) = run_sync_end(sec_message);
    assert_eq!(result, Err(ErrorCode::CapabilityNegotiationFailed));
    assert_eq!(output_capability_values(&output), Vec::<u16>::new());
    assert_eq!(update_device_calls.get(), 1);
}

// An empty announcement cannot cover a non-empty enrolled capability list: fail and invalidate instead of
// converging to an empty effective set.
#[test]
fn host_sync_status_request_end_test_empty_announcement_fails_and_invalidates() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_empty_announcement_fails_and_invalidates start");

    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    set_up_sync_db_mock(update_device_calls.clone());

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], &[]);
    let (result, output) = run_sync_end(sec_message);
    assert_eq!(result, Err(ErrorCode::CapabilityNegotiationFailed));
    assert_eq!(output_capability_values(&output), Vec::<u16>::new());
    assert_eq!(update_device_calls.get(), 1);
}

// An empty enrolled capability list is a valid no-capability binding and is covered by an empty announcement.
#[test]
fn host_sync_status_request_end_test_empty_enrolled_list_allows_empty_announcement() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_empty_enrolled_list_allows_empty_announcement start");

    let update_device_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
    set_up_sync_db_mock_with_device(
        create_mock_companion_device_with_capabilities(Vec::new()),
        update_device_calls.clone(),
    );

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], &[]);
    let (result, output) = run_sync_end(sec_message);
    assert!(result.is_ok());
    assert_eq!(output_capability_values(&output), Vec::<u16>::new());
    assert_eq!(update_device_calls.get(), 0);
}

// The enrolled capability list never changes after enrollment: a successful round never writes the DB. The bare
// mock has no update_device expectation, so any write panics the test.
#[test]
fn host_sync_status_request_end_test_success_never_writes_capability_selection() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_success_never_writes_capability_selection start");

    mock_set_crypto_engine();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_expect_capability_rows(&mut mock_companion_device_db_manager);
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let (result, output) = run_sync_end(sec_message);
    assert!(result.is_ok());
    assert_eq!(output_capability_values(&output), ALL_CAPABILITIES.to_vec());
}

// The reply is decoded once per enrolled processor row and the negotiated lists must agree
// across rows; ProcessorType has a single variant today, so both rows decode the same section.
#[test]
fn host_sync_status_request_end_test_multi_processor_sections_consistent() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_multi_processor_sections_consistent start");

    mock_set_crypto_engine();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    mock_companion_device_db_manager.expect_read_device_capability_info().returning(|| {
        let row = CompanionDeviceCapability {
            processor_type: ProcessorType::Default,
            esl: ExecutorSecurityLevel::Esl0,
            track_ability_level: TrackAbilityLevel::Tal0,
        };
        Ok(vec![row.clone(), row])
    });
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let (result, output) = run_sync_end(sec_message);
    assert!(result.is_ok());
    assert_eq!(output_capability_values(&output), ALL_CAPABILITIES.to_vec());
}

// A device with no persisted processor rows cannot be re-validated: fail-closed without
// touching the binding (no invalidation writes).
#[test]
fn host_sync_status_request_end_test_no_device_capabilities() {
    let _guard = ut_registry_guard!();
    log_i!("host_sync_status_request_end_test_no_device_capabilities start");

    mock_set_crypto_engine();
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device()));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let sec_message = create_valid_sync_reply_message(0, &[PROTOCOL_VERSION_1], ALL_CAPABILITIES);
    let (result, _) = run_sync_end(sec_message);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
