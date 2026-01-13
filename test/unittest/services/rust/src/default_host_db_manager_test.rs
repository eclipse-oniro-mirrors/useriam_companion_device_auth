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
use crate::impls::default_host_db_manager::DefaultHostDbManager;
use crate::log_i;
use crate::traits::crypto_engine::{CryptoEngineRegistry, MockCryptoEngine};
use crate::traits::db_manager::{
    CompanionDeviceBaseInfo, CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk, CompanionTokenInfo,
    DeviceKey, UserInfo,
};
use crate::traits::host_db_manager::HostDbManager;
use crate::traits::storage_io::{MockStorageIo, StorageIoRegistry};
use crate::ut_registry_guard;
use crate::utils::parcel::Parcel;
use std::boxed::Box;

const MAX_DEVICE_NUM: usize = 1;
const MAX_TOKEN_NUM: usize = 1;

fn create_test_device_info(template_id: u64, device_id: &str, user_id: i32) -> CompanionDeviceInfo {
    CompanionDeviceInfo {
        template_id,
        device_key: DeviceKey {
            device_id: device_id.to_string(),
            device_id_type: 1,
            user_id,
        },
        user_info: UserInfo {
            user_id,
            user_type: 1,
        },
        added_time: 1000,
        secure_protocol_id: 1,
        is_valid: true,
    }
}

fn create_test_base_info() -> CompanionDeviceBaseInfo {
    CompanionDeviceBaseInfo {
        device_model: "TestModel".to_string(),
        device_name: "TestDevice".to_string(),
        device_user_name: "TestUser".to_string(),
        business_ids: vec![1, 2, 3],
    }
}

fn create_test_capability_info() -> Vec<CompanionDeviceCapability> {
    vec![CompanionDeviceCapability {
        device_type: DeviceType::None,
        esl: ExecutorSecurityLevel::Esl0,
        track_ability_level: 1,
    }]
}

fn create_test_sk_info() -> Vec<CompanionDeviceSk> {
    vec![CompanionDeviceSk {
        device_type: DeviceType::None,
        sk: vec![1u8, 2, 3, 4],
    }]
}

fn create_test_token_info(template_id: u64) -> CompanionTokenInfo {
    CompanionTokenInfo {
        template_id,
        device_type: DeviceType::None,
        token: vec![1u8, 2, 3, 4],
        atl: AuthTrustLevel::Atl3,
        added_time: 1000,
    }
}

fn mock_set_storage_io_success() {
    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Ok(()));
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    mock_storage_io.expect_delete().returning(|| Ok(()));
    mock_storage_io.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io));
}

#[test]
fn default_host_db_manager_new_test() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_new_test start");

    let manager = DefaultHostDbManager::new();
    assert_eq!(manager.companion_device_infos.len(), 0);
    assert_eq!(manager.companion_token_infos.len(), 0);
}

#[test]
fn default_host_db_manager_add_device_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_add_device_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let result = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);
    assert!(result.is_ok());
    assert_eq!(manager.companion_device_infos.len(), 1);
    assert!(manager.get_device(123).is_ok());
}

#[test]
fn default_host_db_manager_add_device_test_empty_device_id() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_add_device_test_empty_device_id start");

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let result = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_host_db_manager_add_device_test_reach_max() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_add_device_test_reach_max start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    for i in 0..MAX_DEVICE_NUM {
        let device_info = create_test_device_info((100 + i) as u64, &format!("device{}", i), 100);
        let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);
    }

    assert_eq!(manager.companion_device_infos.len(), MAX_DEVICE_NUM);

    let new_device = create_test_device_info(999, "new_device", 100);
    let result = manager.add_device(&new_device, &base_info, &capability_info, &sk_info);
    assert_eq!(result, Err(ErrorCode::ExceedLimit));
}

#[test]
fn default_host_db_manager_add_device_test_write_extra_file_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_add_device_test_write_extra_file_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Err(ErrorCode::GeneralError));
    mock_storage_io.expect_delete().returning(|| Ok(()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let result = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);
    assert_eq!(result, Err(ErrorCode::GeneralError));
    assert_eq!(manager.companion_device_infos.len(), 0);
}

#[test]
fn default_host_db_manager_add_device_test_write_db_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_add_device_test_write_db_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(move |file_name, _| {
        if file_name.contains("companion_device_db") {
            Err(ErrorCode::GeneralError)
        } else {
            Ok(())
        }
    });
    mock_storage_io.expect_delete().returning(|| Ok(()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let result = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);
    assert_eq!(result, Err(ErrorCode::GeneralError));
    assert_eq!(manager.companion_device_infos.len(), 0);
}

#[test]
fn default_host_db_manager_get_device_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_get_device_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);

    let result = manager.get_device(123);
    assert!(result.is_ok());
    let retrieved_device = result.unwrap();
    assert_eq!(retrieved_device.template_id, 123);
    assert_eq!(retrieved_device.device_key.device_id, "device1");
}

#[test]
fn default_host_db_manager_get_device_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_get_device_test_not_found start");

    let manager = DefaultHostDbManager::new();

    let result = manager.get_device(999);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_host_db_manager_get_device_list_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_get_device_list_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let device_info1 = create_test_device_info(123, "device1", 100);
    let device_info2 = create_test_device_info(456, "device2", 200);

    let _ = manager.add_device(&device_info1, &base_info, &capability_info, &sk_info);
    let _ = manager.add_device(&device_info2, &base_info, &capability_info, &sk_info);

    let filter = Box::new(|device: &CompanionDeviceInfo| device.user_info.user_id == 100);
    let devices = manager.get_device_list(filter);
    assert_eq!(devices.len(), 1);
}

#[test]
fn default_host_db_manager_get_device_list_test_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_get_device_list_test_empty start");

    let manager = DefaultHostDbManager::new();

    let filter = Box::new(|_device: &CompanionDeviceInfo| true);
    let devices = manager.get_device_list(filter);
    assert_eq!(devices.len(), 0);
}

#[test]
fn default_host_db_manager_remove_device_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_remove_device_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);
    assert_eq!(manager.companion_device_infos.len(), 1);

    let result = manager.remove_device(123);
    assert!(result.is_ok());
    assert_eq!(manager.companion_device_infos.len(), 0);
}

#[test]
fn default_host_db_manager_remove_device_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_remove_device_test_not_found start");

    let mut manager = DefaultHostDbManager::new();

    let result = manager.remove_device(999);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_host_db_manager_remove_device_test_write_db_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_remove_device_test_write_db_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Ok(()));
    mock_storage_io.expect_delete().returning(|| Ok(()));
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    mock_storage_io.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);
    assert_eq!(manager.companion_device_infos.len(), 1);

    // Set up mock to fail on write
    let mut mock_storage_io_fail = MockStorageIo::new();
    mock_storage_io_fail.expect_write().returning(|_, _| Err(ErrorCode::GeneralError));
    mock_storage_io_fail.expect_delete().returning(|| Ok(()));
    mock_storage_io_fail.expect_read().returning(|| Ok(Vec::new()));
    mock_storage_io_fail.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io_fail));

    let result = manager.remove_device(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
    assert_eq!(manager.companion_device_infos.len(), 1);
}

#[test]
fn default_host_db_manager_update_device_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_update_device_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);

    let mut updated_device = device_info.clone();
    updated_device.is_valid = false;

    let result = manager.update_device(&updated_device);
    assert!(result.is_ok());
    let retrieved = manager.get_device(123).unwrap();
    assert_eq!(retrieved.is_valid, false);
}

#[test]
fn default_host_db_manager_update_device_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_update_device_test_not_found start");

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(999, "device1", 100);

    let result = manager.update_device(&device_info);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_host_db_manager_update_device_test_write_db_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_update_device_test_write_db_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Ok(()));
    mock_storage_io.expect_delete().returning(|| Ok(()));
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    mock_storage_io.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);

    // Set up mock to fail on write
    let mut mock_storage_io_fail = MockStorageIo::new();
    mock_storage_io_fail.expect_write().returning(|_, _| Err(ErrorCode::GeneralError));
    mock_storage_io_fail.expect_delete().returning(|| Ok(()));
    mock_storage_io_fail.expect_read().returning(|| Ok(Vec::new()));
    mock_storage_io_fail.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io_fail));

    let mut updated_device = device_info.clone();
    updated_device.is_valid = false;

    let result = manager.update_device(&updated_device);
    assert_eq!(result, Err(ErrorCode::GeneralError));
    let retrieved = manager.get_device(123).unwrap();
    assert_eq!(retrieved.is_valid, true);
}

#[test]
fn default_host_db_manager_generate_unique_template_id_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_generate_unique_template_id_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let manager = DefaultHostDbManager::new();

    let result = manager.generate_unique_template_id();
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_generate_unique_template_id_test_crypto_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_generate_unique_template_id_test_crypto_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let manager = DefaultHostDbManager::new();

    let result = manager.generate_unique_template_id();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_generate_unique_template_id_test_collision() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_generate_unique_template_id_test_collision start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();
    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);

    let mut mock_crypto_engine = MockCryptoEngine::new();
    // First call returns 123 (collision), second call returns 200
    mock_crypto_engine.expect_secure_random().returning(|buf| {
        buf[0] = 123;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = 0;
        buf[5] = 0;
        buf[6] = 0;
        buf[7] = 0;
        Ok(())
    });
    mock_crypto_engine.expect_secure_random().returning(|buf| {
        buf[0] = 200;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = 0;
        buf[5] = 0;
        buf[6] = 0;
        buf[7] = 0;
        Ok(())
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let result = manager.generate_unique_template_id();
    assert!(result.is_ok());
    let unique_id = result.unwrap();
    assert_eq!(unique_id, 200);
}

#[test]
fn default_host_db_manager_generate_unique_template_id_test_max_attempts() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_generate_unique_template_id_test_max_attempts start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Ok(()));
    mock_storage_io.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|buf| {
        // Always return 123 to trigger max attempts
        buf[0] = 123;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = 0;
        buf[5] = 0;
        buf[6] = 0;
        buf[7] = 0;
        Ok(())
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut manager = DefaultHostDbManager::new();
    // Add device with template_id=123, so secure_random will always collide
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();
    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);

    let result = manager.generate_unique_template_id();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_add_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_add_token_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);

    let token_info = create_test_token_info(123);
    let result = manager.add_token(&token_info);
    assert!(result.is_ok());
    assert_eq!(manager.companion_token_infos.len(), 1);
}

#[test]
fn default_host_db_manager_add_token_test_empty_token() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_add_token_test_empty_token start");

    let mut manager = DefaultHostDbManager::new();
    let mut token_info = create_test_token_info(123);
    token_info.token = vec![];

    let result = manager.add_token(&token_info);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_host_db_manager_add_token_test_template_id_not_exists() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_add_token_test_template_id_not_exists start");

    let mut manager = DefaultHostDbManager::new();
    let token_info = create_test_token_info(999);

    let result = manager.add_token(&token_info);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_host_db_manager_get_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_get_token_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);

    let token_info = create_test_token_info(123);
    let _ = manager.add_token(&token_info);

    let result = manager.get_token(123, DeviceType::None);
    assert!(result.is_ok());
    let retrieved = result.unwrap();
    assert_eq!(retrieved.template_id, 123);
    assert_eq!(retrieved.token, vec![1u8, 2, 3, 4]);
}

#[test]
fn default_host_db_manager_get_token_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_get_token_test_not_found start");

    let manager = DefaultHostDbManager::new();

    let result = manager.get_token(999, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_host_db_manager_remove_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_remove_token_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);

    let token_info = create_test_token_info(123);
    let _ = manager.add_token(&token_info);
    assert_eq!(manager.companion_token_infos.len(), 1);

    let result = manager.remove_token(123, DeviceType::None);
    assert!(result.is_ok());
    assert_eq!(manager.companion_token_infos.len(), 0);
}

#[test]
fn default_host_db_manager_remove_token_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_remove_token_test_not_found start");

    let mut manager = DefaultHostDbManager::new();

    let result = manager.remove_token(999, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_host_db_manager_update_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_update_token_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultHostDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let base_info = create_test_base_info();
    let capability_info = create_test_capability_info();
    let sk_info = create_test_sk_info();

    let _ = manager.add_device(&device_info, &base_info, &capability_info, &sk_info);

    let token_info = create_test_token_info(123);
    let _ = manager.add_token(&token_info);

    let mut updated_token = token_info.clone();
    updated_token.token = vec![5u8, 6, 7, 8];

    let result = manager.update_token(&updated_token);
    assert!(result.is_ok());
    let retrieved = manager.get_token(123, DeviceType::None).unwrap();
    assert_eq!(retrieved.token, vec![5u8, 6, 7, 8]);
}

#[test]
fn default_host_db_manager_update_token_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_update_token_test_not_found start");

    let mut manager = DefaultHostDbManager::new();
    let token_info = create_test_token_info(999);

    let result = manager.update_token(&token_info);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_host_db_manager_read_device_db_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_success start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_u64(123);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(100);
    parcel.write_i32(1);
    parcel.write_u64(1000);
    parcel.write_u16(1);
    parcel.write_u32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert!(result.is_ok());
    assert_eq!(manager.companion_device_infos.len(), 1);
    assert!(manager.get_device(123).is_ok());
}

#[test]
fn default_host_db_manager_read_device_db_test_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_empty start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_read_device_db_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_version_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_version_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(vec![1, 2, 3]));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_count_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_count_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_negative_count() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_negative_count start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(-1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_template_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_template_id_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_device_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_device_id_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_u64(123);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_device_id_type_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_device_id_type_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_u64(123);
    parcel.write_string("device1");

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_user_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_user_id_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_u64(123);
    parcel.write_string("device1");
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_user_info_user_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_user_info_user_id_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_u64(123);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_user_info_user_type_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_user_info_user_type_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_u64(123);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(100);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_added_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_added_time_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_u64(123);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(100);
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_secure_protocol_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_secure_protocol_id_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_u64(123);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(100);
    parcel.write_i32(1);
    parcel.write_u64(1000);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_db_test_deserialize_is_valid_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_db_test_deserialize_is_valid_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_u64(123);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(100);
    parcel.write_i32(1);
    parcel.write_u64(1000);
    parcel.write_u16(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultHostDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_base_info_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_base_info_test_success start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_string("TestModel");
    parcel.write_string("TestDevice");
    parcel.write_string("TestUser");
    parcel.write_i32(3);
    parcel.write_i32(1);
    parcel.write_i32(2);
    parcel.write_i32(3);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_base_info(123);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_read_device_base_info_test_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_base_info_test_empty start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_base_info(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_read_device_base_info_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_base_info_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_base_info(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_read_device_base_info_test_deserialize_missing_version() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_base_info_test_deserialize_missing_version start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(vec![1, 2, 3]));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_base_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_base_info_test_deserialize_missing_model() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_base_info_test_deserialize_missing_model start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_base_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_base_info_test_deserialize_missing_name() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_base_info_test_deserialize_missing_name start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_string("TestModel");

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_base_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_base_info_test_deserialize_missing_user_name() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_base_info_test_deserialize_missing_user_name start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_string("TestModel");
    parcel.write_string("TestDevice");

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_base_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_base_info_test_deserialize_missing_len() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_base_info_test_deserialize_missing_len start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_string("TestModel");
    parcel.write_string("TestDevice");
    parcel.write_string("TestUser");

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_base_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_base_info_test_deserialize_missing_business_id() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_base_info_test_deserialize_missing_business_id start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_string("TestModel");
    parcel.write_string("TestDevice");
    parcel.write_string("TestUser");
    parcel.write_i32(3);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_base_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_write_device_base_info_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_write_device_base_info_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultHostDbManager::new();
    let base_info = create_test_base_info();

    let result = manager.write_device_base_info(123, &base_info);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_write_device_base_info_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_write_device_base_info_test_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let base_info = create_test_base_info();

    let result = manager.write_device_base_info(123, &base_info);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_delete_device_base_info_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_delete_device_base_info_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultHostDbManager::new();

    let result = manager.delete_device_base_info(123);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_delete_device_base_info_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_delete_device_base_info_test_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_delete().returning(|| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();

    let result = manager.delete_device_base_info(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_success start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_i32(DeviceType::None as i32);
    parcel.write_i32(ExecutorSecurityLevel::Esl0 as i32);
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_empty start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_deserialize_miss_version() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_deserialize_miss_version start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(vec![1, 2, 3]));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_deserialize_miss_count() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_deserialize_miss_count start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_deserialize_negative_count() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_deserialize_negative_count start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(-1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_deserialize_miss_type() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_deserialize_miss_type start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_deserialize_miss_esl() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_deserialize_miss_esl start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_i32(DeviceType::None as i32);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_deserialize_miss_level() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_deserialize_miss_level start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_i32(DeviceType::None as i32);
    parcel.write_i32(ExecutorSecurityLevel::Esl0 as i32);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_deserialize_type_convert_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_deserialize_type_convert_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_i32(999);
    parcel.write_i32(ExecutorSecurityLevel::Esl0 as i32);
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_host_db_manager_read_device_capability_info_test_deserialize_esl_convert_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_capability_info_test_deserialize_esl_convert_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_i32(DeviceType::None as i32);
    parcel.write_i32(999);
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_host_db_manager_write_device_capability_info_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_write_device_capability_info_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultHostDbManager::new();
    let capability_info = create_test_capability_info();

    let result = manager.write_device_capability_info(123, &capability_info);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_write_device_capability_info_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_write_device_capability_info_test_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let capability_info = create_test_capability_info();

    let result = manager.write_device_capability_info(123, &capability_info);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_delete_device_capability_info_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_delete_device_capability_info_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultHostDbManager::new();

    let result = manager.delete_device_capability_info(123);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_delete_device_capability_info_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_delete_device_capability_info_test_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_delete().returning(|| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();

    let result = manager.delete_device_capability_info(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_read_device_sk_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_success start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_i32(DeviceType::None as i32);
    parcel.write_i32(4);
    parcel.write_bytes(&[1, 2, 3, 4]);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_read_device_sk_test_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_empty start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_read_device_sk_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_read_device_sk_test_deserialize_miss_version() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_deserialize_miss_version start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(vec![1, 2, 3]));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_sk_test_deserialize_miss_count() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_deserialize_miss_count start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_sk_test_deserialize_negative_count() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_deserialize_negative_count start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(-1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_host_db_manager_read_device_sk_test_deserialize_miss_type() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_deserialize_miss_type start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_sk_test_deserialize_type_convert_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_deserialize_type_convert_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_i32(999);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_host_db_manager_read_device_sk_test_deserialize_miss_len() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_deserialize_miss_len start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_i32(DeviceType::None as i32);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_read_device_sk_test_deserialize_miss_sk() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_read_device_sk_test_deserialize_miss_sk start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_i32(DeviceType::None as i32);
    parcel.write_i32(4);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_host_db_manager_write_device_sk_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_write_device_sk_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultHostDbManager::new();
    let sk_info = create_test_sk_info();

    let result = manager.write_device_sk(123, &sk_info);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_write_device_sk_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_write_device_sk_test_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();
    let sk_info = create_test_sk_info();

    let result = manager.write_device_sk(123, &sk_info);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_host_db_manager_delete_device_sk_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_delete_device_sk_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultHostDbManager::new();

    let result = manager.delete_device_sk(123);
    assert!(result.is_ok());
}

#[test]
fn default_host_db_manager_delete_device_sk_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_db_manager_delete_device_sk_test_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_delete().returning(|| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultHostDbManager::new();

    let result = manager.delete_device_sk(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
