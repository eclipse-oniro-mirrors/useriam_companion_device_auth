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
use crate::singleton_registry;
#[cfg(any(test, feature = "test-utils"))]
use mockall::automock;

#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait StorageIo {
    fn exists(&self, file_name: &str) -> Result<bool, ErrorCode>;
    fn read(&self, file_name: &str) -> Result<crate::Vec<u8>, ErrorCode>;
    fn write(&self, file_name: &str, data: &[u8]) -> Result<(), ErrorCode>;
    fn delete(&self, file_name: &str) -> Result<(), ErrorCode>;
}

pub struct DummyStorageIo;

impl StorageIo for DummyStorageIo {
    fn exists(&self, _file_name: &str) -> Result<bool, ErrorCode> {
        crate::log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn read(&self, _file_name: &str) -> Result<crate::Vec<u8>, ErrorCode> {
        crate::log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn write(&self, _file_name: &str, _data: &[u8]) -> Result<(), ErrorCode> {
        crate::log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn delete(&self, _file_name: &str) -> Result<(), ErrorCode> {
        crate::log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(StorageIoRegistry, StorageIo, DummyStorageIo);
