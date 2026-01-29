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
use crate::impls::default_companion_db_manager::{DefaultCompanionDbManager, MAX_DEVICE_NUM_PER_USER};
use crate::log_i;
use crate::traits::companion_db_manager::CompanionDbManager;
use crate::traits::crypto_engine::{CryptoEngineRegistry, MockCryptoEngine};
use crate::traits::db_manager::{DeviceKey, HostDeviceInfo, HostDeviceSk, HostTokenInfo, UserInfo};
use crate::traits::storage_io::{MockStorageIo, StorageIoRegistry};
use crate::ut_registry_guard;
use crate::utils::parcel::Parcel;
use std::boxed::Box;

fn create_test_device_info(binding_id: i32, device_id: &str, user_id: i32) -> HostDeviceInfo {
    HostDeviceInfo {
        device_key: DeviceKey { device_id: device_id.to_string(), device_id_type: 1, user_id },
        binding_id,
        user_info: UserInfo { user_id, user_type: 1 },
        binding_time: 1000,
        last_used_time: 2000,
    }
}

fn create_test_sk_info(sk: Vec<u8>) -> HostDeviceSk {
    HostDeviceSk { sk: [0u8; SHARE_KEY_LEN] }
}

fn create_test_token_info() -> HostTokenInfo {
    HostTokenInfo { token: [0u8; TOKEN_KEY_LEN], atl: AuthTrustLevel::Atl3 }
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
fn default_companion_db_manager_new_test() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_new_test start");

    let manager = DefaultCompanionDbManager::new();
    assert_eq!(manager.get_device_list(0).len(), 0);
}

#[test]
fn default_companion_db_manager_add_device_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_add_device_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let result = manager.add_device(&device_info, &sk_info);
    assert!(result.is_ok());
    assert!(manager.get_device_by_binding_id(123).is_ok());
    assert_eq!(manager.get_device_list(100).len(), 1);
}

#[test]
fn default_companion_db_manager_add_device_test_empty_device_id() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_add_device_test_empty_device_id start");

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let result = manager.add_device(&device_info, &sk_info);
    assert_eq!(result, Err(ErrorCode::BadParam));
    assert_eq!(manager.get_device_list(100).len(), 0);
}

#[test]
fn default_companion_db_manager_add_device_test_device_key_exists() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_add_device_test_device_key_exists start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info, &sk_info);

    let mut device_info2 = device_info.clone();
    device_info2.binding_id = 456;

    let result = manager.add_device(&device_info2, &sk_info);
    assert_eq!(result, Err(ErrorCode::BadParam));
    assert_eq!(manager.get_device_list(100).len(), 1);
}

#[test]
fn default_companion_db_manager_add_device_test_binding_id_exists() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_add_device_test_binding_id_exists start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info1 = create_test_device_info(123, "device1", 100);
    let device_info2 = create_test_device_info(123, "device2", 200);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info1, &sk_info);

    let result = manager.add_device(&device_info2, &sk_info);
    assert_eq!(result, Err(ErrorCode::BadParam));
    assert_eq!(manager.get_device_list(100).len(), 1);
}

#[test]
fn default_companion_db_manager_add_device_test_max_devices_per_user() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_add_device_test_max_devices_per_user start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let user_id = 100;
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    for i in 0..MAX_DEVICE_NUM_PER_USER {
        let device_info = create_test_device_info((100 + i) as i32, &format!("device{}", i), user_id);
        let _ = manager.add_device(&device_info, &sk_info);
    }

    assert_eq!(manager.get_device_list(user_id).len(), MAX_DEVICE_NUM_PER_USER);

    let new_device = create_test_device_info(999, "new_device", user_id);
    let result = manager.add_device(&new_device, &sk_info);
    assert!(result.is_ok());
    assert_eq!(manager.get_device_list(user_id).len(), MAX_DEVICE_NUM_PER_USER);
}

#[test]
fn default_companion_db_manager_add_device_test_write_db_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_add_device_test_write_db_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|file_name, _| {
        if file_name.contains("host_device_db") {
            Err(ErrorCode::GeneralError)
        } else {
            Ok(())
        }
    });
    mock_storage_io.expect_delete().returning(|| Ok(()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let result = manager.add_device(&device_info, &sk_info);
    assert_eq!(result, Err(ErrorCode::GeneralError));
    assert_eq!(manager.get_device_list(100).len(), 0);
}

#[test]
fn default_companion_db_manager_get_device_by_binding_id_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_get_device_by_binding_id_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info, &sk_info);

    let result = manager.get_device_by_binding_id(123);
    assert!(result.is_ok());
    let retrieved_device = result.unwrap();
    assert_eq!(retrieved_device.binding_id, 123);
    assert_eq!(retrieved_device.device_key.device_id, "device1");
}

#[test]
fn default_companion_db_manager_get_device_by_binding_id_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_get_device_by_binding_id_test_not_found start");

    let manager = DefaultCompanionDbManager::new();

    let result = manager.get_device_by_binding_id(999);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_companion_db_manager_get_device_by_device_key_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_get_device_by_device_key_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info, &sk_info);

    let device_key = DeviceKey { device_id: "device1".to_string(), device_id_type: 1, user_id: 100 };

    let result = manager.get_device_by_device_key(100, &device_key);
    assert!(result.is_ok());
    let retrieved_device = result.unwrap();
    assert_eq!(retrieved_device.binding_id, 123);
}

#[test]
fn default_companion_db_manager_get_device_by_device_key_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_get_device_by_device_key_test_not_found start");

    let manager = DefaultCompanionDbManager::new();

    let device_key = DeviceKey { device_id: "device999".to_string(), device_id_type: 1, user_id: 100 };

    let result = manager.get_device_by_device_key(100, &device_key);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_companion_db_manager_remove_device_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_remove_device_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info, &sk_info);
    assert_eq!(manager.get_device_list(100).len(), 1);

    let result = manager.remove_device(123);
    assert!(result.is_ok());
    assert_eq!(manager.get_device_list(100).len(), 0);
}

#[test]
fn default_companion_db_manager_remove_device_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_remove_device_test_not_found start");

    let mut manager = DefaultCompanionDbManager::new();

    let result = manager.remove_device(999);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_companion_db_manager_remove_device_test_write_db_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_remove_device_test_write_db_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Ok(()));
    mock_storage_io.expect_delete().returning(|| Ok(()));
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    mock_storage_io.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info, &sk_info);
    assert_eq!(manager.get_device_list(100).len(), 1);

    // Set up mock to fail on write
    let mut mock_storage_io_fail = MockStorageIo::new();
    mock_storage_io_fail
        .expect_write()
        .returning(|_, _| Err(ErrorCode::GeneralError));
    mock_storage_io_fail.expect_delete().returning(|| Ok(()));
    mock_storage_io_fail.expect_read().returning(|| Ok(Vec::new()));
    mock_storage_io_fail.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io_fail));

    let result = manager.remove_device(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
    assert_eq!(manager.get_device_list(100).len(), 1);
}

#[test]
fn default_companion_db_manager_update_device_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_update_device_test_success start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info, &sk_info);

    let mut updated_device = device_info.clone();
    updated_device.last_used_time = 5000;

    let result = manager.update_device(&updated_device);
    assert!(result.is_ok());
    let retrieved = manager.get_device_by_binding_id(123).unwrap();
    assert_eq!(retrieved.last_used_time, 5000);
}

#[test]
fn default_companion_db_manager_update_device_test_binding_id_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_update_device_test_binding_id_not_found start");

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(999, "device1", 100);

    let result = manager.update_device(&device_info);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_companion_db_manager_update_device_test_device_key_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_update_device_test_device_key_not_found start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info, &sk_info);

    let mut different_device = device_info.clone();
    different_device.device_key.device_id = "device999".to_string();

    let result = manager.update_device(&different_device);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_companion_db_manager_update_device_test_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_update_device_test_mismatch start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info1 = create_test_device_info(123, "device1", 100);
    let device_info2 = create_test_device_info(456, "device2", 200);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info1, &sk_info);
    let _ = manager.add_device(&device_info2, &sk_info);

    let mut mismatched_device = device_info2.clone();
    mismatched_device.binding_id = 123;

    let result = manager.update_device(&mismatched_device);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_companion_db_manager_update_device_test_write_db_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_update_device_test_write_db_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Ok(()));
    mock_storage_io.expect_delete().returning(|| Ok(()));
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    mock_storage_io.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);

    let _ = manager.add_device(&device_info, &sk_info);

    // Set up mock to fail on write
    let mut mock_storage_io_fail = MockStorageIo::new();
    mock_storage_io_fail
        .expect_write()
        .returning(|_, _| Err(ErrorCode::GeneralError));
    mock_storage_io_fail.expect_delete().returning(|| Ok(()));
    mock_storage_io_fail.expect_read().returning(|| Ok(Vec::new()));
    mock_storage_io_fail.expect_exists().returning(|| Ok(true));
    StorageIoRegistry::set(Box::new(mock_storage_io_fail));

    let mut updated_device = device_info.clone();
    updated_device.last_used_time = 5000;

    let result = manager.update_device(&updated_device);
    assert_eq!(result, Err(ErrorCode::GeneralError));
    let retrieved = manager.get_device_by_binding_id(123).unwrap();
    assert_eq!(retrieved.last_used_time, 2000);
}

#[test]
fn default_companion_db_manager_generate_unique_binding_id_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_generate_unique_binding_id_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
    let manager = DefaultCompanionDbManager::new();

    let result = manager.generate_unique_binding_id();
    assert!(result.is_ok());
}

#[test]
fn default_companion_db_manager_generate_unique_binding_id_test_crypto_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_generate_unique_binding_id_test_crypto_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let manager = DefaultCompanionDbManager::new();

    let result = manager.generate_unique_binding_id();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_companion_db_manager_generate_unique_binding_id_test_collision() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_generate_unique_binding_id_test_collision start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);
    let _ = manager.add_device(&device_info, &sk_info);

    let mut mock_crypto_engine = MockCryptoEngine::new();
    // First call returns 123 (collision with existing device), second call returns 200
    mock_crypto_engine.expect_secure_random().returning(|buf| {
        buf[0] = 123;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        Ok(())
    });
    mock_crypto_engine.expect_secure_random().returning(|buf| {
        buf[0] = 200;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        Ok(())
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let result = manager.generate_unique_binding_id();
    assert!(result.is_ok());
    let unique_id = result.unwrap();
    assert_eq!(unique_id, 200);
}

#[test]
fn default_companion_db_manager_generate_unique_binding_id_test_max_attempts() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_generate_unique_binding_id_test_max_attempts start");

    mock_set_storage_io_success();

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);
    let _ = manager.add_device(&device_info, &sk_info);

    // Set up mock AFTER device is added, returns 123 (collision) repeatedly
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|buf| {
        // Always return 123 to trigger max attempts (collision with existing device)
        buf[0] = 123;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        Ok(())
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut manager = DefaultCompanionDbManager::new();
    let device_info = create_test_device_info(123, "device1", 100);
    let sk_info = create_test_sk_info(vec![1u8, 2, 3]);
    let _ = manager.add_device(&device_info, &sk_info);

    let result = manager.generate_unique_binding_id();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_success start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(123);
    parcel.write_i32(100);
    parcel.write_i32(1);
    parcel.write_u64(1000);
    parcel.write_u64(2000);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert!(result.is_ok());
    assert!(manager.get_device_by_binding_id(123).is_ok());
    let retrieved = manager.get_device_by_binding_id(123).unwrap();
    assert_eq!(retrieved.device_key.device_id, "device1");
}

#[test]
fn default_companion_db_manager_read_device_db_test_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_empty start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert!(result.is_ok());
}

#[test]
fn default_companion_db_manager_read_device_db_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_version_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_version_fail start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(vec![1, 2, 3]));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_count_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_count_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_device_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_device_id_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_device_id_type_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_device_id_type_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_string("device1");

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_user_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_user_id_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_string("device1");
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_binding_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_binding_id_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_user_info_user_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_user_info_user_id_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(123);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_user_info_user_type_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_user_info_user_type_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(123);
    parcel.write_i32(100);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_binding_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_binding_time_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(123);
    parcel.write_i32(100);
    parcel.write_i32(1);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_db_test_deserialize_last_used_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_db_test_deserialize_last_used_time_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(1);
    parcel.write_string("device1");
    parcel.write_i32(1);
    parcel.write_i32(100);
    parcel.write_i32(123);
    parcel.write_i32(100);
    parcel.write_i32(1);
    parcel.write_u64(1000);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let mut manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_db();
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_token_test_success start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(4);
    parcel.write_bytes(&[1, 2, 3, 4]);
    parcel.write_i32(AuthTrustLevel::Atl3 as i32);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_token(123);
    assert!(result.is_ok());
    let token_info = result.unwrap();
    assert_eq!(token_info.token, [0u8; TOKEN_KEY_LEN]);
    assert_eq!(token_info.atl, AuthTrustLevel::Atl3);
}

#[test]
fn default_companion_db_manager_read_device_token_test_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_token_test_empty start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_token(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_companion_db_manager_read_device_token_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_token_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Err(ErrorCode::NotFound));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_token(123);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_companion_db_manager_read_device_token_test_miss_version() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_token_test_miss_version start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(vec![1, 2, 3]));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_token(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_token_test_version_too_high() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_token_test_version_too_high start");

    let mut parcel = Parcel::new();
    parcel.write_i32(999);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_token(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_companion_db_manager_read_device_token_test_miss_token_len() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_token_test_miss_token_len start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_token(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_token_test_miss_token() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_token_test_miss_token start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(4);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_token(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_token_test_miss_atl() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_token_test_miss_atl start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(4);
    parcel.write_bytes(&[1, 2, 3, 4]);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_token(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_token_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_token_test_atl_try_from_fail start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(4);
    parcel.write_bytes(&[1, 2, 3, 4]);
    parcel.write_i32(99999);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_token(123);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn default_companion_db_manager_write_device_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_write_device_token_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultCompanionDbManager::new();
    let token_info = create_test_token_info();

    let result = manager.write_device_token(123, &token_info);
    assert!(result.is_ok());
}

#[test]
fn default_companion_db_manager_write_device_token_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_write_device_token_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let token_info = create_test_token_info();

    let result = manager.write_device_token(123, &token_info);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_companion_db_manager_delete_device_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_delete_device_token_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultCompanionDbManager::new();

    let result = manager.delete_device_token(123);
    assert!(result.is_ok());
}

#[test]
fn default_companion_db_manager_delete_device_token_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_delete_device_token_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_delete().returning(|| Err(ErrorCode::NotFound));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();

    let result = manager.delete_device_token(123);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_companion_db_manager_is_device_token_valid_test_exists() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_is_device_token_valid_test_exists start");

    mock_set_storage_io_success();

    let manager = DefaultCompanionDbManager::new();

    let result = manager.is_device_token_valid(123);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);
}

#[test]
fn default_companion_db_manager_is_device_token_valid_test_not_exists() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_is_device_token_valid_test_not_exists start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_exists().returning(|| Ok(false));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();

    let result = manager.is_device_token_valid(123);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn default_companion_db_manager_is_device_token_valid_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_is_device_token_valid_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_exists().returning(|| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();

    let result = manager.is_device_token_valid(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_companion_db_manager_read_device_sk_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_sk_test_success start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(3);
    parcel.write_bytes(&[1, 2, 3]);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_sk(123);
    assert!(result.is_ok());
    let sk_info = result.unwrap();
    assert_eq!(sk_info.sk, [0u8; SHARE_KEY_LEN]);
}

#[test]
fn default_companion_db_manager_read_device_sk_test_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_sk_test_empty start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(Vec::new()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_companion_db_manager_read_device_sk_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_sk_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Err(ErrorCode::NotFound));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn default_companion_db_manager_read_device_sk_test_miss_version() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_sk_test_miss_version start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(|| Ok(vec![1, 2, 3]));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_sk_test_sk_len() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_sk_test_sk_len start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_read_device_sk_test_miss_sk() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_read_device_sk_test_miss_sk start");

    let mut parcel = Parcel::new();
    parcel.write_i32(0);
    parcel.write_i32(3);

    let serialized_data = parcel.as_slice().to_vec();

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_read().returning(move || Ok(serialized_data.clone()));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let result = manager.read_device_sk(123);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn default_companion_db_manager_write_device_sk_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_write_device_sk_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultCompanionDbManager::new();
    let sk_info = create_test_sk_info(vec![1, 2, 3]);

    let result = manager.write_device_sk(123, &sk_info);
    assert!(result.is_ok());
}

#[test]
fn default_companion_db_manager_write_device_sk_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_write_device_sk_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_write().returning(|_, _| Err(ErrorCode::GeneralError));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();
    let sk_info = create_test_sk_info(vec![1, 2, 3]);

    let result = manager.write_device_sk(123, &sk_info);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn default_companion_db_manager_delete_device_sk_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_delete_device_sk_test_success start");

    mock_set_storage_io_success();

    let manager = DefaultCompanionDbManager::new();

    let result = manager.delete_device_sk(123);
    assert!(result.is_ok());
}

#[test]
fn default_companion_db_manager_delete_device_sk_test_storage_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_companion_db_manager_delete_device_sk_test_storage_error start");

    let mut mock_storage_io = MockStorageIo::new();
    mock_storage_io.expect_delete().returning(|| Err(ErrorCode::NotFound));
    StorageIoRegistry::set(Box::new(mock_storage_io));

    let manager = DefaultCompanionDbManager::new();

    let result = manager.delete_device_sk(123);
    assert_eq!(result, Err(ErrorCode::NotFound));
}
