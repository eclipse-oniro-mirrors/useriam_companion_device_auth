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
use crate::traits::db_manager::{DeviceKey, HostDeviceInfo, HostDeviceSk, HostTokenInfo};
use crate::CString;
use crate::{log_e, singleton_registry, Box, Vec};

pub type HostDeviceFilter = Box<dyn Fn(&HostDeviceInfo) -> bool>;
pub trait CompanionDbManager {
    fn add_device(&mut self, device_info: &HostDeviceInfo, sk_info: &HostDeviceSk) -> Result<(), ErrorCode>;
    fn get_device_by_binding_id(&self, binding_id: i32) -> Result<HostDeviceInfo, ErrorCode>;
    fn get_device_by_device_key(&self, user_id: i32, device_key: &DeviceKey) -> Result<HostDeviceInfo, ErrorCode>;
    fn remove_device(&mut self, binding_id: i32) -> Result<HostDeviceInfo, ErrorCode>;
    fn update_device(&mut self, device_info: &HostDeviceInfo) -> Result<(), ErrorCode>;

    fn generate_unique_binding_id(&self) -> Result<i32, ErrorCode>;

    fn read_device_db(&mut self) -> Result<(), ErrorCode>;

    fn read_device_token(&self, binding_id: i32) -> Result<HostTokenInfo, ErrorCode>;
    fn write_device_token(&self, binding_id: i32, token: &HostTokenInfo) -> Result<(), ErrorCode>;
    fn delete_device_token(&self, binding_id: i32) -> Result<(), ErrorCode>;
    fn is_device_token_valid(&self, binding_id: i32) -> Result<bool, ErrorCode>;

    fn read_device_sk(&self, binding_id: i32) -> Result<HostDeviceSk, ErrorCode>;
    fn write_device_sk(&self, binding_id: i32, sk_info: &HostDeviceSk) -> Result<(), ErrorCode>;
    fn delete_device_sk(&self, binding_id: i32) -> Result<(), ErrorCode>;

    fn get_device_list(&self, user_id: i32) -> Vec<HostDeviceInfo>;
}

struct DummyCompanionDbManager;

impl CompanionDbManager for DummyCompanionDbManager {
    fn add_device(&mut self, _device_info: &HostDeviceInfo, _sk_info: &HostDeviceSk) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device_by_binding_id(&self, _binding_id: i32) -> Result<HostDeviceInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device_by_device_key(&self, _user_id: i32, _device_key: &DeviceKey) -> Result<HostDeviceInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn remove_device(&mut self, _binding_id: i32) -> Result<HostDeviceInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn update_device(&mut self, _device_info: &HostDeviceInfo) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn generate_unique_binding_id(&self) -> Result<i32, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn read_device_db(&mut self) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn read_device_token(&self, _binding_id: i32) -> Result<HostTokenInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn write_device_token(&self, _binding_id: i32, _token: &HostTokenInfo) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn delete_device_token(&self, _binding_id: i32) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn is_device_token_valid(&self, _binding_id: i32) -> Result<bool, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn read_device_sk(&self, _binding_id: i32) -> Result<HostDeviceSk, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn write_device_sk(&self, _binding_id: i32, _sk_info: &HostDeviceSk) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn delete_device_sk(&self, _binding_id: i32) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn get_device_list(&self, _user_id: i32) -> Vec<HostDeviceInfo> {
        log_e!("not implemented");
        Vec::new()
    }
}

singleton_registry!(CompanionDbManagerRegistry, CompanionDbManager, DummyCompanionDbManager);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::db_manager::{DeviceKey, UserInfo};

    #[test]
    fn dummy_companion_db_manager_test() {
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
}
