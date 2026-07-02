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
const FILE_ID: u16 = TestFileId::HostBindingDbHelperTest as u16;

use crate::common::constants::*;
use crate::jobs::host_binding_db_helper::{add_host_binding, update_host_binding_last_used_time};
use crate::log_i;
use crate::traits::db_manager::{DeviceKey, HostBinding, HostBindingSk, UserInfo};
use crate::traits::host_binding_db_manager::{HostBindingDbManagerRegistry, MockHostBindingDbManager};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;

fn create_mock_host_binding(binding_id: i32) -> HostBinding {
    HostBinding {
        device_key: DeviceKey { device_id: String::from("host_device"), device_id_type: 1, user_id: 100 },
        binding_id,
        user_info: UserInfo { user_id: 100, user_type: 0 },
        binding_time: 123456,
        last_used_time: 123456,
    }
}

#[test]
fn add_host_binding_test() {
    let _guard = ut_registry_guard!();
    log_i!("add_host_binding_test start");

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_get_device_by_device_key().returning(|| Ok(create_mock_host_binding(123)));
    mock_host_binding_db_manager.expect_remove_device().returning(|| Ok(create_mock_host_binding(123)));
    mock_host_binding_db_manager.expect_add_device().returning(|| Ok(None));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let device_info = create_mock_host_binding(456);
    let sk_info = HostBindingSk { sk: [0u8; SHARE_KEY_LEN] };

    let result = add_host_binding(&device_info, &sk_info);
    assert!(result.is_ok());
}

#[test]
fn update_host_binding_last_used_time_test_get_device_by_binding_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("update_host_binding_last_used_time_test_get_device_by_binding_id_fail start");

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_get_device_by_binding_id().returning(|| Err(ErrorCode::NotFound));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let result = update_host_binding_last_used_time(123);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn update_host_binding_last_used_time_test_get_rtc_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("update_host_binding_last_used_time_test_get_rtc_time_fail start");

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_get_device_by_binding_id().returning(|| Ok(create_mock_host_binding(123)));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Err(ErrorCode::GeneralError));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let result = update_host_binding_last_used_time(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn update_host_binding_last_used_time_test_update_device_fail() {
    let _guard = ut_registry_guard!();
    log_i!("update_host_binding_last_used_time_test_update_device_fail start");

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_get_device_by_binding_id().returning(|| Ok(create_mock_host_binding(123)));
    mock_host_binding_db_manager.expect_update_device().returning(|| Err(ErrorCode::GeneralError));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let result = update_host_binding_last_used_time(123);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
