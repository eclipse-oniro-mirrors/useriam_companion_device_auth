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
    CompanionProcessCheckInputFfi, CompanionProcessTokenAuthInputFfi, DataArray1024Ffi, DataArray32Ffi,
    Uint16Array64Ffi,
};
use crate::log_i;
use crate::request::status_sync::companion_sync_status::CompanionDeviceSyncStatusRequest;
use crate::traits::companion_db_manager::{CompanionDbManagerRegistry, MockCompanionDbManager};
use crate::traits::crypto_engine::{CryptoEngineRegistry, MockCryptoEngine};
use crate::traits::db_manager::HostDeviceSk;
use crate::traits::request_manager::{Request, RequestParam};
use crate::ut_registry_guard;
use std::boxed::Box;

fn create_valid_input(binding_id: i32, challenge: u64) -> CompanionProcessCheckInputFfi {
    let mut capability_list = Uint16Array64Ffi::default();
    capability_list.data[0] = 0x01;
    capability_list.data[1] = 0x02;
    capability_list.len = 2;

    CompanionProcessCheckInputFfi {
        binding_id,
        capability_list,
        secure_protocol_id: 1,
        salt: DataArray32Ffi { data: [1u8; HKDF_SALT_SIZE], len: HKDF_SALT_SIZE as u32 },
        challenge,
        sec_message: DataArray1024Ffi::default(),
    }
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
    assert_eq!(request.challenge, 0);
    assert_eq!(request.protocol_list, PROTOCOL_VERSION.to_vec());
    assert_eq!(request.capability_list, vec![0x01, 0x02]);
}

#[test]
fn companion_sync_status_request_new_test_capability_list_convert_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_sync_status_request_new_test_capability_list_convert_fail start");

    let mut capability_list = Uint16Array64Ffi::default();
    capability_list.len = 65;

    let input = CompanionProcessCheckInputFfi {
        binding_id: 123,
        capability_list,
        secure_protocol_id: 1,
        salt: DataArray32Ffi { data: [1u8; HKDF_SALT_SIZE], len: HKDF_SALT_SIZE as u32 },
        challenge: 0,
        sec_message: DataArray1024Ffi::default(),
    };
    let result = CompanionDeviceSyncStatusRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::BadParam));
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

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: [0u8; SHARE_KEY_LEN] }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = create_valid_input(123, 0);
    let mut request = CompanionDeviceSyncStatusRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessCheckOutputFfi::default();
    let param = RequestParam::CompanionSyncStatus(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
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
