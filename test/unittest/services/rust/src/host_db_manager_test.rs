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
use crate::log_i;
use crate::traits::db_manager::{
    CompanionDeviceBaseInfo, CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk, CompanionTokenInfo,
    DeviceKey, UserInfo,
};
use crate::traits::host_db_manager::{DummyHostDbManager, HostDbManager};
use crate::ut_registry_guard;

fn create_mock_companion_device_info() -> CompanionDeviceInfo {
    CompanionDeviceInfo {
        template_id: 0,
        device_key: DeviceKey::default(),
        user_info: UserInfo { user_id: 0, user_type: 0 },
        added_time: 0,
        secure_protocol_id: 0,
        is_valid: false,
    }
}

fn create_mock_companion_device_base_info() -> CompanionDeviceBaseInfo {
    CompanionDeviceBaseInfo {
        device_model: String::default(),
        device_name: String::default(),
        device_user_name: String::default(),
        business_ids: Vec::<i32>::new(),
    }
}

fn create_mock_companion_token_info() -> CompanionTokenInfo {
    CompanionTokenInfo {
        template_id: 0,
        device_type: DeviceType::Default,
        token: [0u8; TOKEN_KEY_LEN],
        atl: AuthTrustLevel::Atl0,
        added_time: 0,
    }
}

#[test]
fn dummy_host_db_manager_test() {
    let _guard = ut_registry_guard!();
    log_i!("dummy_host_db_manager_test start");

    let mut dummy_host_db_manager = DummyHostDbManager;
    let device_info = create_mock_companion_device_info();
    let base_info = create_mock_companion_device_base_info();
    let token = create_mock_companion_token_info();

    assert_eq!(
        dummy_host_db_manager.add_device(
            &device_info,
            &base_info,
            &Vec::<CompanionDeviceCapability>::new(),
            &Vec::<CompanionDeviceSk>::new()
        ),
        Err(ErrorCode::GeneralError)
    );
    assert!(dummy_host_db_manager.get_device(0).is_err());
    assert!(dummy_host_db_manager.get_device_list(Box::new(|_| true)).is_empty());
    assert!(dummy_host_db_manager.remove_device(0).is_err());
    assert!(dummy_host_db_manager.update_device(&device_info).is_err());
    assert!(dummy_host_db_manager.generate_unique_template_id().is_err());
    assert!(dummy_host_db_manager.add_token(&token).is_err());
    assert!(dummy_host_db_manager.get_token(0, DeviceType::Default).is_err());
    assert!(dummy_host_db_manager.remove_token(0, DeviceType::Default).is_err());
    assert!(dummy_host_db_manager.update_token(&token).is_err());
    assert!(dummy_host_db_manager.read_device_db().is_err());
    assert!(dummy_host_db_manager.read_device_base_info(0).is_err());
    assert!(dummy_host_db_manager.write_device_base_info(0, &base_info).is_err());
    assert!(dummy_host_db_manager.delete_device_base_info(0).is_err());
    assert!(dummy_host_db_manager.read_device_capability_info(0).is_err());
    assert!(dummy_host_db_manager
        .write_device_capability_info(0, &Vec::<CompanionDeviceCapability>::new())
        .is_err());
    assert!(dummy_host_db_manager.delete_device_capability_info(0).is_err());
    assert!(dummy_host_db_manager.read_device_sk(0).is_err());
    assert!(dummy_host_db_manager
        .write_device_sk(0, &Vec::<CompanionDeviceSk>::new())
        .is_err());
    assert!(dummy_host_db_manager.delete_device_sk(0).is_err());
}
