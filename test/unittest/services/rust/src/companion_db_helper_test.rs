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
use crate::jobs::companion_db_helper::{add_host_device, update_host_device_last_used_time};
use crate::log_i;
use crate::traits::companion_db_manager::{CompanionDbManagerRegistry, MockCompanionDbManager};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::{DeviceKey, HostDeviceInfo, HostDeviceSk, UserInfo};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;

fn create_mock_host_device_info(binding_id: i32) -> HostDeviceInfo {
    HostDeviceInfo {
        device_key: DeviceKey { device_id: String::from("host_device"), device_id_type: 1, user_id: 100 },
        binding_id,
        user_info: UserInfo { user_id: 100, user_type: 0 },
        binding_time: 123456,
        last_used_time: 123456,
    }
}

#[test]
fn add_host_device_test() {
    let _guard = ut_registry_guard!();
    log_i!("add_host_device_test start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_get_device_by_device_key()
        .returning(|| Ok(create_mock_host_device_info(123)));
    mock_companion_db_manager
        .expect_remove_device()
        .returning(|| Ok(create_mock_host_device_info(123)));
    mock_companion_db_manager.expect_add_device().returning(|| Ok(()));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let device_info = create_mock_host_device_info(456);
    let sk_info = HostDeviceSk { sk: Vec::new() };

    let result = add_host_device(&device_info, &sk_info);
    assert!(result.is_ok());
}

#[test]
fn update_host_device_last_used_time_test_get_device_by_binding_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("update_host_device_last_used_time_test_get_device_by_binding_id_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_get_device_by_binding_id()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let result = update_host_device_last_used_time(123);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn update_host_device_last_used_time_test_get_rtc_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("update_host_device_last_used_time_test_get_rtc_time_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_get_device_by_binding_id()
        .returning(|| Ok(create_mock_host_device_info(123)));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper
        .expect_get_rtc_time()
        .returning(|| Err(ErrorCode::GeneralError));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let result = update_host_device_last_used_time(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn update_host_device_last_used_time_test_update_device_fail() {
    let _guard = ut_registry_guard!();
    log_i!("update_host_device_last_used_time_test_update_device_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_get_device_by_binding_id()
        .returning(|| Ok(create_mock_host_device_info(123)));
    mock_companion_db_manager
        .expect_update_device()
        .returning(|| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let result = update_host_device_last_used_time(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
