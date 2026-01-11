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
use crate::traits::host_db_manager::{HostDbManagerRegistry, MockHostDbManager};
use crate::traits::db_manager::{CompanionDeviceBaseInfo, CompanionDeviceInfo, DeviceKey, UserInfo};
use crate::log_i;
use crate::ut_registry_guard;
use crate::jobs::host_db_helper::{update_companion_device_info, update_device_business_id, get_session_key};

fn create_mock_companion_device_base_info() -> CompanionDeviceBaseInfo {
    CompanionDeviceBaseInfo {
        device_model: String::from("TestModel"),
        device_name: String::from("TestDevice"),
        device_user_name: String::from("TestUser"),
        business_ids: vec![1, 2, 3],
    }
}

fn create_mock_companion_device_info(template_id: u64) -> CompanionDeviceInfo {
    CompanionDeviceInfo {
        template_id,
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

#[test]
fn update_companion_device_info_test_write_device_base_info_fail() {
    let _guard = ut_registry_guard!();
    log_i!("update_companion_device_info_test_write_device_base_info_fail start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_read_device_base_info().returning(|| Ok(create_mock_companion_device_base_info()));
    mock_host_db_manager.expect_write_device_base_info().returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let result = update_companion_device_info(123, "name".to_string(), "user_name".to_string());
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn update_device_business_id_test_read_device_base_info_fail() {
    let _guard = ut_registry_guard!();
    log_i!("update_device_business_id_test_read_device_base_info_fail start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_get_device().returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager.expect_read_device_base_info().returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let result = update_device_business_id(123, vec![1, 2, 3]);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn get_session_key_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("get_session_key_test_fail start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_read_device_sk().returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let result = get_session_key(123, DeviceType::None, &[]);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
