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

use crate::commands::common_command::*;
use crate::common::constants::ErrorCode;
use crate::entry::companion_device_auth_ffi::*;
use crate::log_i;
use crate::traits::db_manager::DeviceKey;
use crate::traits::event_manager::{Event, EventType};
use crate::ut_registry_guard;
use std::ffi::CString;

#[test]
fn try_vec_from_array_with_len_test() {
    let _guard = ut_registry_guard!();
    log_i!("try_vec_from_array_with_len_test start");

    let array = [1u8, 2, 3, 4, 5];

    assert!(try_vec_from_array_with_len(&array, 3).is_ok());
    let result = try_vec_from_array_with_len(&array, 3).unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result, vec![1, 2, 3]);

    assert!(try_vec_from_array_with_len(&array, 0).is_ok());
    assert!(try_vec_from_array_with_len(&array, 5).is_ok());

    assert_eq!(try_vec_from_array_with_len(&array, 6), Err(ErrorCode::BadParam));
    assert_eq!(try_vec_from_array_with_len(&array, 100), Err(ErrorCode::BadParam));
}

#[test]
fn try_array_from_vec_test() {
    let _guard = ut_registry_guard!();
    log_i!("try_array_from_vec_test start");

    let vec = vec![1u8, 2, 3];
    let result: Result<([u8; 5], u32), ErrorCode> = try_array_from_vec(vec);
    assert!(result.is_ok());
    let (array, len) = result.unwrap();
    assert_eq!(len, 3);
    assert_eq!(array[0], 1);
    assert_eq!(array[1], 2);
    assert_eq!(array[2], 3);

    let empty_vec: Vec<u8> = Vec::new();
    let result: Result<([u8; 5], u32), ErrorCode> = try_array_from_vec(empty_vec);
    assert!(result.is_ok());
    let (_array, len) = result.unwrap();
    assert_eq!(len, 0);

    let vec = vec![1u8, 2, 3, 4, 5, 6];
    let result: Result<([u8; 5], u32), ErrorCode> = try_array_from_vec(vec);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn data_array_64_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("data_array_64_ffi_test start");

    let vec = vec![1u8, 2, 3, 4, 5];
    let data_array = DataArray64Ffi::try_from(&vec);
    assert!(data_array.is_ok());
    let data_array = data_array.unwrap();

    let slice = data_array.as_slice().unwrap();
    assert_eq!(slice.len(), 5);
    assert_eq!(slice, &[1u8, 2, 3, 4, 5]);

    let vec_result = data_array.to_vec().unwrap();
    assert_eq!(vec_result, vec![1u8, 2, 3, 4, 5]);

    let str_vec = vec![72u8, 101, 108, 108, 111];
    let data_array = DataArray64Ffi::try_from(str_vec).unwrap();
    let string = data_array.to_string();
    assert!(string.is_ok());
    assert_eq!(string.unwrap(), "Hello");

    let invalid_utf8 = vec![0xffu8, 0xfe, 0xfd];
    let data_array = DataArray64Ffi::try_from(invalid_utf8).unwrap();
    assert_eq!(data_array.to_string(), Err(ErrorCode::GeneralError));

    let long_vec = vec![0u8; 100];
    let result = DataArray64Ffi::try_from(&long_vec);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn data_array_128_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("data_array_128_ffi_test start");

    let vec = vec![1u8; 100];
    let data_array = DataArray128Ffi::try_from(&vec);
    assert!(data_array.is_ok());

    let vec = vec![1u8; 129];
    let data_array = DataArray128Ffi::try_from(&vec);
    assert_eq!(data_array, Err(ErrorCode::BadParam));
}

#[test]
fn data_array_256_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("data_array_256_ffi_test start");

    let vec = vec![1u8; 200];
    let data_array = DataArray256Ffi::try_from(&vec);
    assert!(data_array.is_ok());

    let vec = vec![1u8; 257];
    let data_array = DataArray256Ffi::try_from(&vec);
    assert_eq!(data_array, Err(ErrorCode::BadParam));
}

#[test]
fn data_array_1024_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("data_array_1024_ffi_test start");

    let vec = vec![1u8; 1000];
    let data_array = DataArray1024Ffi::try_from(&vec);
    assert!(data_array.is_ok());

    let vec = vec![1u8; 1025];
    let data_array = DataArray1024Ffi::try_from(&vec);
    assert_eq!(data_array, Err(ErrorCode::BadParam));
}

#[test]
fn data_array_20000_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("data_array_20000_ffi_test start");

    // Test normal case
    let vec = vec![1u8; 10000];
    let data_array = DataArray20000Ffi::try_from(&vec);
    assert!(data_array.is_ok());
    let data_array = data_array.unwrap();

    let slice = data_array.as_slice().unwrap();
    assert_eq!(slice.len(), 10000);
    assert_eq!(slice[0], 1);
    assert_eq!(slice[9999], 1);

    // Test at boundary - exactly 20000 bytes
    let vec = vec![0xAAu8; 20000];
    let data_array = DataArray20000Ffi::try_from(&vec);
    assert!(data_array.is_ok());
    let data_array = data_array.unwrap();
    let slice = data_array.as_slice().unwrap();
    assert_eq!(slice.len(), 20000);
    assert_eq!(slice[0], 0xAA);
    assert_eq!(slice[19999], 0xAA);

    // Test to_vec conversion
    let vec_result = data_array.to_vec().unwrap();
    assert_eq!(vec_result.len(), 20000);
    assert_eq!(vec_result[0], 0xAA);
    assert_eq!(vec_result[19999], 0xAA);

    // Test overflow - 20001 bytes should fail
    let vec = vec![1u8; 20001];
    let result = DataArray20000Ffi::try_from(&vec);
    assert_eq!(result, Err(ErrorCode::BadParam));

    // Test from CString
    let str_vec = "Hello, World!".as_bytes().to_vec();
    let data_array = DataArray20000Ffi::try_from(str_vec).unwrap();
    let string = data_array.to_string();
    assert!(string.is_ok());
    assert_eq!(string.unwrap(), "Hello, World!");

    // Test invalid UTF-8
    let invalid_utf8 = vec![0xFFu8, 0xFE, 0xFD];
    let data_array = DataArray20000Ffi::try_from(invalid_utf8).unwrap();
    assert_eq!(data_array.to_string(), Err(ErrorCode::GeneralError));
}

#[test]
fn device_key_ffi_try_from_test() {
    let _guard = ut_registry_guard!();
    log_i!("device_key_ffi_try_from_test start");

    let device_key = DeviceKey { device_id: String::from("test_device_id"), device_id_type: 1, user_id: 100 };

    let device_key_ffi = DeviceKeyFfi::try_from(device_key);
    assert!(device_key_ffi.is_ok());
    let device_key_ffi = device_key_ffi.unwrap();
    assert_eq!(device_key_ffi.device_id_type, 1);
    assert_eq!(device_key_ffi.user_id, 100);

    let long_device_key = DeviceKey { device_id: String::from("a").repeat(100), device_id_type: 1, user_id: 100 };
    let result = DeviceKeyFfi::try_from(long_device_key);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn string_to_data_array_test() {
    let _guard = ut_registry_guard!();
    log_i!("string_to_data_array_test start");

    let string = String::from("Hello");
    let data_array = DataArray128Ffi::try_from(string);
    assert!(data_array.is_ok());

    let string = String::from("World");
    let data_array = DataArray256Ffi::try_from(string);
    assert!(data_array.is_ok());
}

#[test]
fn template_id_array_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("template_id_array_ffi_test start");

    let vec = vec![1u64, 2, 3, 4, 5];
    let template_id_array = TemplateIdArrayFfi::try_from(vec.clone());
    assert!(template_id_array.is_ok());

    let template_id_array = template_id_array.unwrap();
    let vec_result = Vec::<u64>::try_from(template_id_array);
    assert!(vec_result.is_ok());
    assert_eq!(vec_result.unwrap(), vec);

    let long_vec = vec![0u64; 200];
    let result = TemplateIdArrayFfi::try_from(long_vec);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn uint16_array_64_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("uint16_array_64_ffi_test start");

    let vec = vec![1u16, 2, 3, 4, 5];
    let uint16_array = Uint16Array64Ffi::try_from(vec.clone());
    assert!(uint16_array.is_ok());

    let uint16_array = uint16_array.unwrap();
    let vec_result = Vec::<u16>::try_from(uint16_array);
    assert!(vec_result.is_ok());
    assert_eq!(vec_result.unwrap(), vec);

    let long_vec = vec![0u16; 100];
    let result = Uint16Array64Ffi::try_from(long_vec);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn int32_array_64_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("int32_array_64_ffi_test start");

    let vec = vec![1i32, 2, 3, 4, 5];
    let int32_array = Int32Array64Ffi::try_from(vec.clone());
    assert!(int32_array.is_ok());

    let int32_array = int32_array.unwrap();
    let vec_result = Vec::<i32>::try_from(int32_array);
    assert!(vec_result.is_ok());
    assert_eq!(vec_result.unwrap(), vec);

    let long_vec = vec![0i32; 100];
    let result = Int32Array64Ffi::try_from(long_vec);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_status_vec_to_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("companion_status_vec_to_ffi_test start");

    let vec = vec![PersistedCompanionStatusFfi::default()];
    let mut array = CompanionStatusArrayFfi::default();
    let result = companion_status_vec_to_ffi(vec, &mut array);
    assert!(result.is_ok());
    assert_eq!(array.len, 1);

    let vec = vec![PersistedCompanionStatusFfi::default(); 200];
    let mut array = CompanionStatusArrayFfi::default();
    let result = companion_status_vec_to_ffi(vec, &mut array);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_binding_status_vec_to_ffi_test() {
    let _guard = ut_registry_guard!();
    log_i!("host_binding_status_vec_to_ffi_test start");

    let vec = vec![PersistedHostBindingStatusFfi::default()];
    let mut array = HostBindingStatusArrayFfi::default();
    let result = host_binding_status_vec_to_ffi(vec, &mut array);
    assert!(result.is_ok());
    assert_eq!(array.len, 1);

    let vec = vec![PersistedHostBindingStatusFfi::default(); 200];
    let mut array = HostBindingStatusArrayFfi::default();
    let result = host_binding_status_vec_to_ffi(vec, &mut array);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn common_output_try_from_test() {
    let _guard = ut_registry_guard!();
    log_i!("common_output_try_from_test start");

    let common_output = CommonOutput { result: ErrorCode::Success, has_fatal_error: false, events: Vec::new() };

    let common_output_ffi = CommonOutputFfi::try_from(common_output);
    assert!(common_output_ffi.is_ok());
    let common_output_ffi = common_output_ffi.unwrap();
    assert_eq!(common_output_ffi.result, ErrorCode::Success as i32);
    assert_eq!(common_output_ffi.has_fatal_error, 0);

    let event = Event {
        time: 12345,
        file_name: CString::new("test.rs").unwrap(),
        line_number: 100,
        event_type: EventType::Error,
        event_info: CString::new("test event").unwrap(),
    };

    let common_output = CommonOutput { result: ErrorCode::GeneralError, has_fatal_error: true, events: vec![event] };

    let common_output_ffi = CommonOutputFfi::try_from(common_output);
    assert!(common_output_ffi.is_ok());
    let common_output_ffi = common_output_ffi.unwrap();
    assert_eq!(common_output_ffi.result, ErrorCode::GeneralError as i32);
    assert_eq!(common_output_ffi.has_fatal_error, 1);
    assert_eq!(common_output_ffi.events.len, 1);
}
