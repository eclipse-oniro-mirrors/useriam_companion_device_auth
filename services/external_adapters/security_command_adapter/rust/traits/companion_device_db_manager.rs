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

use crate::common::constants::{ErrorCode, ProcessorType};
use crate::traits::db_manager::{
    CompanionDevice, CompanionDeviceCapability, CompanionDeviceProfile, CompanionDeviceSk, CompanionDeviceToken,
};
use crate::traits::log_trace::RustFileId;
use crate::{log_e, singleton_registry, Box, Vec};
pub(crate) const FILE_ID: u16 = RustFileId::CompanionDeviceDbManager as u16;

pub type CompanionDeviceFilter = Box<dyn Fn(&CompanionDevice) -> bool>;
pub type CompanionTokenFilter = Box<dyn Fn(&CompanionDeviceToken) -> bool>;

pub trait CompanionDeviceDbManager {
    fn add_device(
        &mut self,
        device_info: &CompanionDevice,
        base_info: &CompanionDeviceProfile,
        capability_info: &[CompanionDeviceCapability],
        sk_info: &[CompanionDeviceSk],
    ) -> Result<(), ErrorCode>;
    fn get_device(&self, template_id: u64) -> Result<CompanionDevice, ErrorCode>;
    fn get_device_list(&self, filter: CompanionDeviceFilter) -> Vec<CompanionDevice>;
    fn remove_device(&mut self, template_id: u64) -> Result<CompanionDevice, ErrorCode>;
    fn update_device(&mut self, _device_info: &CompanionDevice) -> Result<(), ErrorCode>;

    fn generate_unique_template_id(&self) -> Result<u64, ErrorCode>;

    fn add_token(&mut self, token: &CompanionDeviceToken) -> Result<(), ErrorCode>;
    fn get_token(&self, template_id: u64, processor_type: ProcessorType) -> Result<CompanionDeviceToken, ErrorCode>;
    fn remove_token(
        &mut self,
        template_id: u64,
        processor_type: ProcessorType,
    ) -> Result<CompanionDeviceToken, ErrorCode>;
    fn update_token(&mut self, device_info: &CompanionDeviceToken) -> Result<(), ErrorCode>;

    fn read_device_db(&mut self) -> Result<(), ErrorCode>;

    fn read_device_profile(&self, template_id: u64) -> Result<CompanionDeviceProfile, ErrorCode>;
    fn write_device_profile(&self, template_id: u64, base_info: &CompanionDeviceProfile) -> Result<(), ErrorCode>;
    fn delete_device_profile(&self, template_id: u64) -> Result<(), ErrorCode>;
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

pub struct DummyCompanionDeviceDbManager;

impl CompanionDeviceDbManager for DummyCompanionDeviceDbManager {
    fn add_device(
        &mut self,
        _device_info: &CompanionDevice,
        _base_info: &CompanionDeviceProfile,
        _capability_info: &[CompanionDeviceCapability],
        _sk_info: &[CompanionDeviceSk],
    ) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device(&self, _template_id: u64) -> Result<CompanionDevice, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device_list(&self, _filter: CompanionDeviceFilter) -> Vec<CompanionDevice> {
        log_e!("not implemented");
        Vec::new()
    }
    fn remove_device(&mut self, _template_id: u64) -> Result<CompanionDevice, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn update_device(&mut self, _device_info: &CompanionDevice) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn generate_unique_template_id(&self) -> Result<u64, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn add_token(&mut self, _token: &CompanionDeviceToken) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_token(&self, _template_id: u64, _processor_type: ProcessorType) -> Result<CompanionDeviceToken, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn remove_token(
        &mut self,
        _template_id: u64,
        _processor_type: ProcessorType,
    ) -> Result<CompanionDeviceToken, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn update_token(&mut self, _device_info: &CompanionDeviceToken) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn read_device_db(&mut self) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn read_device_profile(&self, _template_id: u64) -> Result<CompanionDeviceProfile, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn write_device_profile(&self, _template_id: u64, _base_info: &CompanionDeviceProfile) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn delete_device_profile(&self, _template_id: u64) -> Result<(), ErrorCode> {
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

singleton_registry!(CompanionDeviceDbManagerRegistry, CompanionDeviceDbManager, DummyCompanionDeviceDbManager);

#[cfg(any(test, feature = "test-utils"))]
pub use crate::test_utils::mock::MockCompanionDeviceDbManager;
