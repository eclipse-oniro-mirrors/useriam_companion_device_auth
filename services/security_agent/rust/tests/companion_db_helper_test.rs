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

use rust::common::constants::*;
use rust::common::types::*;
use rust::traits::companion_db_manager::CompanionDbManagerRegistry;
use rust::traits::crypto_engine::CryptoEngineRegistry;
use rust::traits::db_manager::{HostDeviceInfo, HostDeviceSk};
use rust::traits::time_keeper::TimeKeeperRegistry;
use rust::{log_e, log_i, p, Box, Vec};
use rust::ut_registry_guard;

#[test]
fn add_host_device_test() {
    let _guard = ut_registry_guard!();
    log_i!("add_host_device_test start");
    let device_key = DeviceKey {
        device_id: "test_device_id",
        device_id_type: 0,
        user_id: 100
    }

    let user_info = UserInfo {
        user_id: 100,
        user_type: 0
    }

    let device_info = HostDeviceInfo {
        device_key: device_key,
        binding_id: 0,
        user_info: user_info,
        binding_time: 0,
        last_used_time: 0,
        is_token_valid: true
    }

    let sk_info = HostDeviceSk {
        sk: Vec::new()
    }

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_get_device_by_device_key().returning(|_| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));
    assert_eq!(add_host_device(device_info, sk_info), Err(ErrorCode::GeneralError));

    mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_get_device_by_device_key().returning(|_| Ok(device_info));
    mock_companion_db_manager.expect_remove_device(|_| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));
    assert_eq!(add_host_device(device_info, sk_info), Err(ErrorCode::GeneralError));

    mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_get_device_by_device_key().returning(|_| Err(ErrorCode::NotFound));
    mock_companion_db_manager.expect_add_device().returning(|_| Ok(()));
    mock_companion_db_manager.expect_write_device_sk().returning(|_, _| Ok(()));
    mock_companion_db_manager.expect_write_device_db().returning(|| Ok(()));
    assert_eq!(add_host_device(device_info, sk_info), Ok(()));
}

#[test]
fn delete_host_device_test() {
    let _guard = ut_registry_guard!();
    log_i!("delete_host_device_test start");

    let device_key = DeviceKey {
        device_id: "test_device_id",
        device_id_type: 0,
        user_id: 100
    }

    let user_info = UserInfo {
        user_id: 100,
        user_type: 0
    }

    let device_info = HostDeviceInfo {
        device_key: device_key,
        binding_id: 0,
        user_info: user_info,
        binding_time: 0,
        last_used_time: 0,
        is_token_valid: true
    }

    let binding_id = 0;
    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_remove_device(|_| Ok(device_info));
    mock_companion_db_manager.expect_delete_device_sk(|_| Ok(()));
    mock_companion_db_manager.expect_delete_token_db(|_| Ok(()));
    mock_companion_db_manager.expect_write_device_db(|| Ok(()));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));
    assert_eq!(delete_host_device(binding_id), Ok(()));
}