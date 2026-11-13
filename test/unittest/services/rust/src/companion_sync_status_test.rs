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
const FILE_ID: u16 = TestFileId::CompanionSyncStatusTest as u16;

use crate::common::constants::*;

const PROTOCOL_VERSION_1: u16 = 1;
use crate::entry::companion_device_auth_ffi::{
    CompanionProcessCheckInputFfi, CompanionProcessTokenAuthInputFfi, DataArray1024Ffi, DataArray32Ffi,
    Uint16Array64Ffi,
};
use crate::log_i;
use crate::request::status_sync::companion_sync_status::CompanionDeviceSyncStatusRequest;
use crate::traits::crypto_engine::{CryptoEngineRegistry, MockCryptoEngine};
use crate::common::algorithm::SelectedAlgorithms;
use crate::traits::db_manager::{DeviceKey, HostBinding, HostBindingKeyMaterial, UserInfo, UserKey};
use crate::traits::host_binding_db_manager::{HostBindingDbManagerRegistry, MockHostBindingDbManager};
use crate::traits::request_manager::{Request, RequestParam};
use crate::ut_registry_guard;
use std::boxed::Box;

fn create_mock_host_binding(binding_id: i32, secure_protocol_id: u16) -> HostBinding {
    HostBinding {
        device_key: DeviceKey::default(),
        binding_id,
        user_info: UserInfo { user_key: UserKey::default(), user_type: 0 },
        binding_time: 0,
        last_used_time: 0,
        enrolled_protocol_id: PROTOCOL_VERSION_1,
        secure_protocol_id,
    }
}

fn create_valid_input(binding_id: i32, challenge: u64) -> CompanionProcessCheckInputFfi {
    let mut companion_protocol_list = Uint16Array64Ffi::default();
    companion_protocol_list.data[0] = PROTOCOL_VERSION_1;
    companion_protocol_list.len = 1;

    let mut companion_capability_list = Uint16Array64Ffi::default();
    companion_capability_list.data[0] = 0x01;
    companion_capability_list.data[1] = 0x02;
    companion_capability_list.len = 2;

    CompanionProcessCheckInputFfi {
        binding_id,
        companion_protocol_list,
        companion_capability_list,
        secure_protocol_id: 1,
        salt: DataArray32Ffi { data: [1u8; HKDF_SALT_SIZE], len: HKDF_SALT_SIZE as u32 },
        challenge,
    }
}

#[test]
fn companion_sync_status_request_new_test_unsupported_secure_protocol_id() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_new_test_unsupported_secure_protocol_id start");

    let mut input = create_valid_input(123, 0);
    input.secure_protocol_id = 2;
    let result = CompanionDeviceSyncStatusRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::SecureProtocolNotSupported));
}

#[test]
fn companion_sync_status_request_new_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_new_test_success start");

    let input = create_valid_input(123, 0);
    let result = CompanionDeviceSyncStatusRequest::new(&input);
    assert!(result.is_ok());

    let request = result.unwrap();
    assert_eq!(request.get_request_id(), 123);
    assert_eq!(request.host_challenge, 0);
    assert_eq!(request.companion_protocol_list, vec![PROTOCOL_VERSION_1]);
    assert_eq!(request.companion_capability_list, vec![0x01, 0x02]);
}

#[test]
fn companion_sync_status_request_new_test_announces_local_capabilities_verbatim() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_new_test_announces_local_capabilities_verbatim start");

    let mut input = create_valid_input(123, 0);
    input.companion_capability_list = Uint16Array64Ffi::try_from(vec![0x03, 0x02, 0x01, 0x01]).unwrap();

    let request = CompanionDeviceSyncStatusRequest::new(&input).unwrap();
    assert_eq!(request.companion_capability_list, vec![0x03, 0x02, 0x01, 0x01]);
}

#[test]
fn companion_sync_status_request_new_test_companion_capability_list_convert_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_new_test_companion_capability_list_convert_fail start");

    let mut companion_capability_list = Uint16Array64Ffi::default();
    companion_capability_list.len = 65;

    let input = CompanionProcessCheckInputFfi {
        binding_id: 123,
        companion_protocol_list: Uint16Array64Ffi::default(),
        companion_capability_list,
        secure_protocol_id: 1,
        salt: DataArray32Ffi { data: [1u8; HKDF_SALT_SIZE], len: HKDF_SALT_SIZE as u32 },
        challenge: 0,
    };
    let result = CompanionDeviceSyncStatusRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_sync_status_request_new_test_capability_value_not_support() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_new_test_capability_value_not_support start");

    // Boundary check: a capability value outside the Capability enum is rejected fail-closed.
    let mut input = create_valid_input(123, 0);
    input.companion_capability_list = Uint16Array64Ffi::try_from(vec![0x01, 99]).unwrap();

    let result = CompanionDeviceSyncStatusRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_sync_status_request_new_test_capability_value_invalid_zero() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_new_test_capability_value_invalid_zero start");

    // Boundary check: the explicit Invalid(0) capability value is rejected like unknown values.
    let mut input = create_valid_input(123, 0);
    input.companion_capability_list = Uint16Array64Ffi::try_from(vec![0x02, 0]).unwrap();

    let result = CompanionDeviceSyncStatusRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_sync_status_request_prepare_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_prepare_test_not_implemented start");

    let input = create_valid_input(123, 0);
    let mut request = CompanionDeviceSyncStatusRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessCheckOutputFfi::default();
    let param = RequestParam::CompanionSyncStatus(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_sync_status_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_begin_test_wrong_input_type start");

    let input = create_valid_input(123, 0);
    let mut request = CompanionDeviceSyncStatusRequest::new(&input).unwrap();

    let wrong_input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessTokenAuthOutputFfi::default();
    let param = RequestParam::CompanionTokenAuthBegin(&wrong_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_sync_status_request_begin_test_encrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_begin_test_encrypt_sec_message_fail start");

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager
        .expect_get_device_by_binding_id()
        .returning(|| Ok(create_mock_host_binding(123, SecureProtocolId::Default as u16)));
    mock_host_binding_db_manager.expect_read_device_sk().returning(|| Ok(HostBindingKeyMaterial {
        sk: [0u8; SHARE_KEY_LEN],
        selected_algorithms: SelectedAlgorithms {
            ka_algorithm: 1,
            kdf_algorithm: 1,
            aead_algorithm: 1,
            mac_algorithm: 1,
        },
    }));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_secure_random().returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = create_valid_input(123, 0);
    let mut request = CompanionDeviceSyncStatusRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessCheckOutputFfi::default();
    let param = RequestParam::CompanionSyncStatus(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_sync_status_request_begin_test_binding_without_persisted_secure_protocol_rejected() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_begin_test_binding_without_persisted_secure_protocol_rejected start");

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager
        .expect_get_device_by_binding_id()
        .returning(|| Ok(create_mock_host_binding(123, 0)));
    mock_host_binding_db_manager.expect_read_device_sk().returning(|| Ok(HostBindingKeyMaterial {
        sk: [0u8; SHARE_KEY_LEN],
        selected_algorithms: SelectedAlgorithms {
            ka_algorithm: 1,
            kdf_algorithm: 1,
            aead_algorithm: 1,
            mac_algorithm: 1,
        },
    }));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|_data, _| {
        Ok(crate::traits::crypto_engine::AesGcmResult {
            ciphertext: Vec::new(),
            authentication_tag: [0u8; AES_GCM_TAG_SIZE],
        })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = create_valid_input(123, 0);
    let mut request = CompanionDeviceSyncStatusRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessCheckOutputFfi::default();
    let param = RequestParam::CompanionSyncStatus(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::SecureProtocolNotSupported));
}

#[test]
fn companion_sync_status_request_begin_test_uses_enrolled_secure_protocol() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_begin_test_uses_enrolled_secure_protocol start");

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    // A new enrollment protocol must not change the framing of an existing binding;
    // an SA input outside SUPPORTED_PROTOCOL_VERSIONS is rejected at the boundary instead.
    mock_host_binding_db_manager
        .expect_get_device_by_binding_id()
        .returning(|| Ok(create_mock_host_binding(123, SecureProtocolId::Default as u16)));
    mock_host_binding_db_manager.expect_read_device_sk().returning(|| Ok(HostBindingKeyMaterial {
        sk: [0u8; SHARE_KEY_LEN],
        selected_algorithms: SelectedAlgorithms {
            ka_algorithm: 1,
            kdf_algorithm: 1,
            aead_algorithm: 1,
            mac_algorithm: 1,
        },
    }));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|_data, _| {
        Ok(crate::traits::crypto_engine::AesGcmResult {
            ciphertext: Vec::new(),
            authentication_tag: [0u8; AES_GCM_TAG_SIZE],
        })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = create_valid_input(123, 0);
    let mut request = CompanionDeviceSyncStatusRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessCheckOutputFfi::default();
    let param = RequestParam::CompanionSyncStatus(&input, &mut output);
    let result = request.begin(param);
    assert!(result.is_ok());
    assert_eq!(request.secure_protocol_id, SecureProtocolId::Default as u16);
}

#[test]
fn companion_sync_status_request_begin_test_get_binding_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_begin_test_get_binding_fail start");

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager
        .expect_get_device_by_binding_id()
        .returning(|| Err(ErrorCode::NotFound));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let input = create_valid_input(123, 0);
    let mut request = CompanionDeviceSyncStatusRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessCheckOutputFfi::default();
    let param = RequestParam::CompanionSyncStatus(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_sync_status_request_end_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_end_test_not_implemented start");

    let input = create_valid_input(123, 0);
    let mut request = CompanionDeviceSyncStatusRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessCheckOutputFfi::default();
    let param = RequestParam::CompanionSyncStatus(&input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_sync_status_request_new_test_salt_len_exceeds_array() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_new_test_salt_len_exceeds_array start");

    let mut input = create_valid_input(123, 0);
    input.salt.len = (HKDF_SALT_SIZE as u32) + 1;

    let result = CompanionDeviceSyncStatusRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::BadParam));
}
