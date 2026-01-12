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
use crate::traits::db_manager::{DeviceKey, HostDeviceInfo, HostDeviceSk, HostTokenInfo, UserInfo};
use crate::traits::companion_db_manager::{CompanionDbManager, DummyCompanionDbManager};
use crate::ut_registry_guard;

#[test]
fn dummy_companion_db_manager_test() {
    let _guard = ut_registry_guard!();
    log_i!("dummy_companion_db_manager_test start");

    let mut dummy_companion_db_manager = DummyCompanionDbManager;
    let device_info = HostDeviceInfo {
        device_key: DeviceKey::default(),
        binding_id: 0,
        user_info: UserInfo { user_id: 0, user_type: 0 },
        binding_time: 0,
        last_used_time: 0,
    };
    let sk_info = HostDeviceSk { sk: Vec::<u8>::new() };
    let token = HostTokenInfo { token: Vec::<u8>::new(), atl: AuthTrustLevel::Atl0 };

    assert_eq!(dummy_companion_db_manager.add_device(&device_info, &sk_info), Err(ErrorCode::GeneralError));
    assert!(dummy_companion_db_manager.get_device_by_binding_id(0).is_err());
    assert!(dummy_companion_db_manager
        .get_device_by_device_key(100, &DeviceKey::default())
        .is_err());
    assert!(dummy_companion_db_manager.remove_device(0).is_err());
    assert!(dummy_companion_db_manager.update_device(&device_info).is_err());
    assert!(dummy_companion_db_manager.generate_unique_binding_id().is_err());
    assert!(dummy_companion_db_manager.read_device_db().is_err());
    assert!(dummy_companion_db_manager.read_device_token(0).is_err());
    assert!(dummy_companion_db_manager.write_device_token(0, &token).is_err());
    assert!(dummy_companion_db_manager.delete_device_token(0).is_err());
    assert!(dummy_companion_db_manager.is_device_token_valid(0).is_err());
    assert!(dummy_companion_db_manager.read_device_sk(0).is_err());
    assert!(dummy_companion_db_manager.write_device_sk(0, &sk_info).is_err());
    assert!(dummy_companion_db_manager.delete_device_sk(0).is_err());
    assert!(dummy_companion_db_manager.get_device_list(0).is_empty());
}
