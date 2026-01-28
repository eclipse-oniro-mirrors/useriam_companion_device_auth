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
use crate::traits::db_manager::{
    CompanionDeviceBaseInfo, CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk, CompanionTokenInfo,
};
use crate::{log_e, singleton_registry, Box, Vec};

pub type CompanionDeviceFilter = Box<dyn Fn(&CompanionDeviceInfo) -> bool>;
pub type CompanionTokenFilter = Box<dyn Fn(&CompanionTokenInfo) -> bool>;

pub trait HostDbManager {
    fn add_device(
        &mut self,
        device_info: &CompanionDeviceInfo,
        base_info: &CompanionDeviceBaseInfo,
        capability_info: &[CompanionDeviceCapability],
        sk_info: &[CompanionDeviceSk],
    ) -> Result<(), ErrorCode>;
    fn get_device(&self, template_id: u64) -> Result<CompanionDeviceInfo, ErrorCode>;
    fn get_device_list(&self, filter: CompanionDeviceFilter) -> Vec<CompanionDeviceInfo>;
    fn remove_device(&mut self, template_id: u64) -> Result<CompanionDeviceInfo, ErrorCode>;
    fn update_device(&mut self, _device_info: &CompanionDeviceInfo) -> Result<(), ErrorCode>;

    fn generate_unique_template_id(&self) -> Result<u64, ErrorCode>;

    fn add_token(&mut self, token: &CompanionTokenInfo) -> Result<(), ErrorCode>;
    fn get_token(&self, template_id: u64, device_type: DeviceType) -> Result<CompanionTokenInfo, ErrorCode>;
    fn remove_token(&mut self, template_id: u64, device_type: DeviceType) -> Result<CompanionTokenInfo, ErrorCode>;
    fn update_token(&mut self, device_info: &CompanionTokenInfo) -> Result<(), ErrorCode>;

    fn read_device_db(&mut self) -> Result<(), ErrorCode>;

    fn read_device_base_info(&self, template_id: u64) -> Result<CompanionDeviceBaseInfo, ErrorCode>;
    fn write_device_base_info(&self, template_id: u64, base_info: &CompanionDeviceBaseInfo) -> Result<(), ErrorCode>;
    fn delete_device_base_info(&self, template_id: u64) -> Result<(), ErrorCode>;
    fn read_device_capability_info(&self, template_id: u64) -> Result<Vec<CompanionDeviceCapability>, ErrorCode>;
    fn write_device_capability_info(
        &self,
        template_id: u64,
        capability_info: &[CompanionDeviceCapability],
    ) -> Result<(), ErrorCode>;
    fn delete_device_capability_info(&self, template_id: u64) -> Result<(), ErrorCode>;
    fn read_device_sk(&self, template_id: u64) -> Result<Vec<CompanionDeviceSk>, ErrorCode>;
    fn write_device_sk(&self, template_id: u64, sk_info: &[CompanionDeviceSk]) -> Result<(), ErrorCode>;
    fn delete_device_sk(&self, template_id: u64) -> Result<(), ErrorCode>;
}

pub struct DummyHostDbManager;

impl HostDbManager for DummyHostDbManager {
    fn add_device(
        &mut self,
        _device_info: &CompanionDeviceInfo,
        _base_info: &CompanionDeviceBaseInfo,
        _capability_info: &[CompanionDeviceCapability],
        _sk_info: &[CompanionDeviceSk],
    ) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device(&self, _template_id: u64) -> Result<CompanionDeviceInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device_list(&self, _filter: CompanionDeviceFilter) -> Vec<CompanionDeviceInfo> {
        log_e!("not implemented");
        Vec::new()
    }
    fn remove_device(&mut self, _template_id: u64) -> Result<CompanionDeviceInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn update_device(&mut self, _device_info: &CompanionDeviceInfo) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn generate_unique_template_id(&self) -> Result<u64, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn add_token(&mut self, _token: &CompanionTokenInfo) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_token(&self, _template_id: u64, _device_type: DeviceType) -> Result<CompanionTokenInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn remove_token(&mut self, _template_id: u64, _device_type: DeviceType) -> Result<CompanionTokenInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn update_token(&mut self, _device_info: &CompanionTokenInfo) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn read_device_db(&mut self) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn read_device_base_info(&self, _template_id: u64) -> Result<CompanionDeviceBaseInfo, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn write_device_base_info(&self, _template_id: u64, _base_info: &CompanionDeviceBaseInfo) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn delete_device_base_info(&self, _template_id: u64) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn read_device_capability_info(&self, _template_id: u64) -> Result<Vec<CompanionDeviceCapability>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn write_device_capability_info(
        &self,
        _template_id: u64,
        _capability_info: &[CompanionDeviceCapability],
    ) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn delete_device_capability_info(&self, _template_id: u64) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn read_device_sk(&self, _template_id: u64) -> Result<Vec<CompanionDeviceSk>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn write_device_sk(&self, _template_id: u64, _sk_info: &[CompanionDeviceSk]) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn delete_device_sk(&self, _template_id: u64) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(HostDbManagerRegistry, HostDbManager, DummyHostDbManager);

#[cfg(any(test, feature = "test-utils"))]
pub use crate::test_utils::mock::MockHostDbManager;
