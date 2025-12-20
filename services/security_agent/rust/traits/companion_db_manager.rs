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
    fn add_device(&mut self, device_info: &HostDeviceInfo) -> Result<(), ErrorCode>;
    fn get_device_by_device_key(&self, device_key: &DeviceKey)
        -> Result<HostDeviceInfo, ErrorCode>;
    fn get_device(&self, filter: HostDeviceFilter) -> Result<HostDeviceInfo, ErrorCode>;
    fn remove_device_by_device_key(
        &mut self,
        device_key: &DeviceKey,
    ) -> Result<HostDeviceInfo, ErrorCode>;
    fn remove_device(&mut self, filter: HostDeviceFilter) -> Result<HostDeviceInfo, ErrorCode>;
    fn update_device(&mut self, device_info: &HostDeviceInfo) -> Result<(), ErrorCode>;

    fn generate_unique_binding_id(&self) -> Result<i32, ErrorCode>;

    fn read_device_db(&mut self) -> Result<(), ErrorCode>;
    fn write_device_db(&mut self) -> Result<(), ErrorCode>;
    fn clean_device_db(&mut self) -> Result<(), ErrorCode>;

    fn read_token_db(&mut self, binding_id: i32) -> Result<HostTokenInfo, ErrorCode>;
    fn write_token_db(&mut self, binding_id: i32, token: &HostTokenInfo) -> Result<(), ErrorCode>;
    fn delete_token_db(&mut self, binding_id: i32) -> Result<(), ErrorCode>;

    fn read_device_sk(&mut self, binding_id: i32) -> Result<HostDeviceSk, ErrorCode>;
    fn write_device_sk(&mut self, binding_id: i32, sk_info: &HostDeviceSk)
        -> Result<(), ErrorCode>;
    fn delete_device_sk(&mut self, binding_id: i32) -> Result<(), ErrorCode>;

    fn get_device_list(&mut self, user_id: i32) -> Result<Vec<HostDeviceInfo>, ErrorCode>;
}

struct DummyCompanionDbManager;

impl CompanionDbManager for DummyCompanionDbManager {
    fn add_device(&mut self, _device_info: &HostDeviceInfo) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device_by_device_key(
        &self,
        _device_key: &DeviceKey,
    ) -> Result<HostDeviceInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device(&self, _filter: HostDeviceFilter) -> Result<HostDeviceInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn remove_device_by_device_key(
        &mut self,
        _device_key: &DeviceKey,
    ) -> Result<HostDeviceInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn remove_device(&mut self, _filter: HostDeviceFilter) -> Result<HostDeviceInfo, ErrorCode> {
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
    fn write_device_db(&mut self) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn clean_device_db(&mut self) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn read_token_db(&mut self, _binding_id: i32) -> Result<HostTokenInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn write_token_db(
        &mut self,
        _binding_id: i32,
        _token: &HostTokenInfo,
    ) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn delete_token_db(&mut self, _binding_id: i32) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn read_device_sk(&mut self, _binding_id: i32) -> Result<HostDeviceSk, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn write_device_sk(
        &mut self,
        _binding_id: i32,
        _sk_info: &HostDeviceSk,
    ) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn delete_device_sk(&mut self, _binding_id: i32) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn get_device_list(&mut self, _user_id: i32) -> Result<Vec<HostDeviceInfo>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(
    CompanionDbManagerRegistry,
    CompanionDbManager,
    DummyCompanionDbManager
);
