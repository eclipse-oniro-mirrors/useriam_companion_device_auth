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

use crate::common::constants::ErrorCode;
use crate::traits::db_manager::{DeviceKey, HostBinding, HostBindingSk, HostBindingToken};
use crate::traits::log_trace::RustFileId;
use crate::{log_e, singleton_registry, Box, Vec};
pub(crate) const FILE_ID: u16 = RustFileId::HostBindingDbManager as u16;

pub trait HostBindingDbManager {
    fn add_device(&mut self, device_info: &HostBinding, sk_info: &HostBindingSk) -> Result<Option<i32>, ErrorCode>;
    fn get_device_by_binding_id(&self, binding_id: i32) -> Result<HostBinding, ErrorCode>;
    fn get_device_by_device_key(&self, user_id: i32, device_key: &DeviceKey) -> Result<HostBinding, ErrorCode>;
    fn remove_device(&mut self, binding_id: i32) -> Result<HostBinding, ErrorCode>;
    fn update_device(&mut self, device_info: &HostBinding) -> Result<(), ErrorCode>;

    fn generate_unique_binding_id(&self) -> Result<i32, ErrorCode>;

    fn read_device_db(&mut self) -> Result<(), ErrorCode>;

    fn read_device_token(&self, binding_id: i32) -> Result<HostBindingToken, ErrorCode>;
    fn write_device_token(&self, binding_id: i32, token: &HostBindingToken) -> Result<(), ErrorCode>;
    fn delete_device_token(&self, binding_id: i32) -> Result<(), ErrorCode>;
    fn is_device_token_valid(&self, binding_id: i32) -> Result<bool, ErrorCode>;

    fn read_device_sk(&self, binding_id: i32) -> Result<HostBindingSk, ErrorCode>;
    fn write_device_sk(&self, binding_id: i32, sk_info: &HostBindingSk) -> Result<(), ErrorCode>;
    fn delete_device_sk(&self, binding_id: i32) -> Result<(), ErrorCode>;

    fn get_device_list(&self, user_id: i32) -> Vec<HostBinding>;
}

pub struct DummyHostBindingDbManager;

impl HostBindingDbManager for DummyHostBindingDbManager {
    fn add_device(&mut self, _device_info: &HostBinding, _sk_info: &HostBindingSk) -> Result<Option<i32>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device_by_binding_id(&self, _binding_id: i32) -> Result<HostBinding, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_device_by_device_key(&self, _user_id: i32, _device_key: &DeviceKey) -> Result<HostBinding, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn remove_device(&mut self, _binding_id: i32) -> Result<HostBinding, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn update_device(&mut self, _device_info: &HostBinding) -> Result<(), ErrorCode> {
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
    fn read_device_token(&self, _binding_id: i32) -> Result<HostBindingToken, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn write_device_token(&self, _binding_id: i32, _token: &HostBindingToken) -> Result<(), ErrorCode> {
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

    fn read_device_sk(&self, _binding_id: i32) -> Result<HostBindingSk, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn write_device_sk(&self, _binding_id: i32, _sk_info: &HostBindingSk) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn delete_device_sk(&self, _binding_id: i32) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn get_device_list(&self, _user_id: i32) -> Vec<HostBinding> {
        log_e!("not implemented");
        Vec::new()
    }
}

singleton_registry!(HostBindingDbManagerRegistry, HostBindingDbManager, DummyHostBindingDbManager);

#[cfg(any(test, feature = "test-utils"))]
pub use crate::test_utils::mock::MockHostBindingDbManager;
