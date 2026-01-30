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

use crate::impls::default_storage_io::DefaultStorageIo;
use crate::log_i;
use crate::traits::storage_io::StorageIo;
use crate::ut_registry_guard;
use std::fs;

/// RAII guard to ensure test files are deleted even if the test panics
struct FileGuard<'a> {
    file_path: &'a str,
}

impl<'a> FileGuard<'a> {
    fn new(file_path: &'a str) -> Self {
        Self { file_path }
    }
}

impl<'a> Drop for FileGuard<'a> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.file_path);
    }
}

#[test]
fn default_storage_io_new_test() {
    let _guard = ut_registry_guard!();
    log_i!("default_storage_io_new_test start");

    let storage = DefaultStorageIo::new();
    let result = storage.exists("some_file");
    assert!(result.is_ok());
}

#[test]
fn default_storage_io_write_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_storage_io_write_test_success start");

    let storage = DefaultStorageIo::new();
    let data = vec![1u8, 2, 3, 4, 5];
    let test_file = "non_existence_file.txt";

    // RAII guard ensures file is deleted even if test panics
    let _file_guard = FileGuard::new(test_file);

    let result = storage.write(test_file, &data);
    assert!(result.is_ok(), "write operation should succeed");
}

#[test]
fn default_storage_io_read_test_not_exist() {
    let _guard = ut_registry_guard!();
    log_i!("default_storage_io_read_test_not_exist start");

    let storage = DefaultStorageIo::new();

    // Clean up environment: ensure file doesn't exist before testing
    let _ = storage.delete("non_existence_file.txt");

    let result = storage.read("non_existence_file.txt");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn default_storage_io_delete_test_not_exist() {
    let _guard = ut_registry_guard!();
    log_i!("default_storage_io_delete_test_not_exist start");

    let storage = DefaultStorageIo::new();

    // Clean up environment: ensure file doesn't exist before testing
    let _ = storage.delete("non_existence_file.txt");

    let result = storage.delete("non_existence_file.txt");
    assert!(result.is_ok());
}
