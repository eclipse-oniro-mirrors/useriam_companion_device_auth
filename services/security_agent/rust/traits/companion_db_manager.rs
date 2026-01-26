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

use crate::traits::db_manager::{DeviceKey, HostDeviceInfo, HostDeviceSk, HostTokenInfo};

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

pub struct DummyCompanionDbManager;

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

#[cfg(any(test, feature = "test-utils"))]
pub use crate::test_utils::mock::MockCompanionDbManager;
