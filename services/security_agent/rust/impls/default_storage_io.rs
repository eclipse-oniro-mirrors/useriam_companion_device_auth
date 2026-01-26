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
use crate::log_e;
use crate::traits::storage_io::StorageIo;
use crate::{CString, Vec};
#[cfg(not(any(test, feature = "test-utils")))]
use alloc::format;
#[cfg(any(test, feature = "test-utils"))]
use std::format;

#[allow(unused_extern_crates)]
extern crate std;
use std::fs;
use std::path::Path;

const DEFAULT_FILE_HEAD: &str = "/data/service/el1/public/companiondeviceauth/";

pub struct DefaultStorageIo;

impl DefaultStorageIo {
    pub fn new() -> Self {
        Self
    }
}

impl StorageIo for DefaultStorageIo {
    fn exists(&self, file_name: &str) -> Result<bool, ErrorCode> {
        let final_path = format!("{}{}", DEFAULT_FILE_HEAD, file_name);
        return Ok(Path::new(&final_path).exists());
    }

    fn read(&self, file_name: &str) -> Result<crate::Vec<u8>, ErrorCode> {
        match self.exists(file_name) {
            Ok(exists) => {
                if !exists {
                    log_e!("file is not exist: {}", file_name);
                    return Ok(Vec::new());
                }
            },
            Err(e) => {
                log_e!("failed to check file exist: {:?}", e);
                return Err(e);
            },
        }

        let final_path = format!("{}{}", DEFAULT_FILE_HEAD, file_name);
        let context = fs::read(final_path).map_err(|e| {
            log_e!("failed to read file: {}, result: {:?}", file_name, e);
            ErrorCode::GeneralError
        })?;
        Ok(context)
    }

    fn write(&self, file_name: &str, data: &[u8]) -> Result<(), ErrorCode> {
        let final_path = format!("{}{}", DEFAULT_FILE_HEAD, file_name);
        fs::write(&final_path, data).map_err(|e| {
            log_e!("failed to write file: {}, result: {:?}", file_name, e);
            ErrorCode::GeneralError
        })?;

        #[cfg(unix)]
        {
            use libc::{chmod, S_IRUSR, S_IWUSR};
            let c_path = CString::new(final_path.as_str()).map_err(|e| {
                log_e!("failed to create CString: {}, result: {:?}", file_name, e);
                ErrorCode::GeneralError
            })?;

            unsafe {
                // 0o600 = S_IRUSR | S_IWUSR (owner read/write)
                let mode = S_IRUSR | S_IWUSR;
                if chmod(c_path.as_ptr(), mode) != 0 {
                    log_e!("failed to set file permissions: {}", file_name);
                    return Err(ErrorCode::GeneralError);
                }
            }
        }

        Ok(())
    }

    fn delete(&self, file_name: &str) -> Result<(), ErrorCode> {
        if !self.exists(file_name)? {
            log_e!("file is not exist: {}", file_name);
            return Ok(());
        }
        let final_path = format!("{}{}", DEFAULT_FILE_HEAD, file_name);
        fs::remove_file(final_path).map_err(|e| {
            log_e!("failed to delete file: {}, result: {:?}", file_name, e);
            ErrorCode::GeneralError
        })?;
        Ok(())
    }
}

impl Default for DefaultStorageIo {
    fn default() -> Self {
        Self::new()
    }
}
