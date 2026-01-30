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
use crate::log_i;
use crate::ut_registry_guard;
use crate::utils::parcel::Parcel;

#[test]
fn test_parcel_new() {
    let _guard = ut_registry_guard!();
    log_i!("test_parcel_new start");

    let parcel = Parcel::new();
    assert_eq!(parcel.data.len(), 0);
    assert_eq!(parcel.read_pos, 0);
}

#[test]
fn test_parcel_from_vec() {
    let _guard = ut_registry_guard!();
    log_i!("test_parcel_from_vec start");

    let data = vec![1, 2, 3, 4, 5];
    let parcel = Parcel::from(data.clone());
    assert_eq!(parcel.data, data);
    assert_eq!(parcel.read_pos, 0);
}

#[test]
fn test_write_read_u8() {
    let _guard = ut_registry_guard!();
    log_i!("test_write_read_u8 start");

    let mut parcel = Parcel::new();
    let test_value: u8 = 0xAB;

    parcel.write_u8(test_value);
    assert_eq!(parcel.data.len(), 1);

    parcel.read_pos = 0;
    let read_value = parcel.read_u8().unwrap();
    assert_eq!(read_value, test_value);
}

#[test]
fn test_write_read_u32() {
    let _guard = ut_registry_guard!();
    log_i!("test_write_read_u32 start");

    let mut parcel = Parcel::new();
    let test_value: u32 = 0xDEADBEEF;

    parcel.write_u32(test_value);
    assert_eq!(parcel.data.len(), 4);

    parcel.read_pos = 0;
    let read_value = parcel.read_u32().unwrap();
    assert_eq!(read_value, test_value);
}

#[test]
fn test_write_read_u32_le() {
    let _guard = ut_registry_guard!();
    log_i!("test_write_read_u32_le start");

    let mut parcel = Parcel::new();
    let test_value: u32 = 0x12345678;

    parcel.write_u32_le(test_value);

    parcel.read_pos = 0;
    let read_value = parcel.read_u32_le().unwrap();
    assert_eq!(read_value, test_value);
}

#[test]
fn test_write_read_u64() {
    let _guard = ut_registry_guard!();
    log_i!("test_write_read_u64 start");

    let mut parcel = Parcel::new();
    let test_value: u64 = 0xCAFEBABEDEADBEEF;

    parcel.write_u64(test_value);
    assert_eq!(parcel.data.len(), 8);

    parcel.read_pos = 0;
    let read_value = parcel.read_u64().unwrap();
    assert_eq!(read_value, test_value);
}

#[test]
fn test_write_read_i8() {
    let _guard = ut_registry_guard!();
    log_i!("test_write_read_i8 start");

    let mut parcel = Parcel::new();
    let test_value: i8 = -42;

    parcel.write_i8(test_value);

    parcel.read_pos = 0;
    let read_value = parcel.read_i8().unwrap();
    assert_eq!(read_value, test_value);
}

#[test]
fn test_write_read_i32() {
    let _guard = ut_registry_guard!();
    log_i!("test_write_read_i32 start");

    let mut parcel = Parcel::new();
    let test_value: i32 = -123456789;

    parcel.write_i32(test_value);

    parcel.read_pos = 0;
    let read_value = parcel.read_i32().unwrap();
    assert_eq!(read_value, test_value);
}

#[test]
fn test_write_read_i32_le() {
    let _guard = ut_registry_guard!();
    log_i!("test_write_read_i32_le start");

    let mut parcel = Parcel::new();
    let test_value: i32 = -12345;

    parcel.write_i32_le(test_value);

    parcel.read_pos = 0;
    let read_value = parcel.read_i32_le().unwrap();
    assert_eq!(read_value, test_value);
}

#[test]
fn test_write_read_i64() {
    let _guard = ut_registry_guard!();
    log_i!("test_write_read_i64 start");

    let mut parcel = Parcel::new();
    let test_value: i64 = -1234567890123456789;

    parcel.write_i64(test_value);

    parcel.read_pos = 0;
    let read_value = parcel.read_i64().unwrap();
    assert_eq!(read_value, test_value);
}

#[test]
fn test_write_read_bytes() {
    let _guard = ut_registry_guard!();
    log_i!("test_write_read_bytes start");

    let mut parcel = Parcel::new();
    let test_bytes = vec![1, 2, 3, 4, 5, 6, 7, 8];

    parcel.write_bytes(&test_bytes);
    assert_eq!(parcel.data.len(), test_bytes.len());

    parcel.read_pos = 0;
    let mut read_bytes = vec![0u8; test_bytes.len()];
    parcel.read_bytes(&mut read_bytes).unwrap();
    assert_eq!(read_bytes, test_bytes);
}

#[test]
fn test_multiple_writes_reads() {
    let _guard = ut_registry_guard!();
    log_i!("test_multiple_writes_reads start");

    let mut parcel = Parcel::new();

    // Write various data types
    parcel.write_u8(0x12);
    parcel.write_u32(0x34567890);
    parcel.write_i32(-12345);
    parcel.write_bytes(&[1, 2, 3, 4]);

    // Reset read_position for reading
    parcel.read_pos = 0;

    // Read back in order
    assert_eq!(parcel.read_u8().unwrap(), 0x12);
    assert_eq!(parcel.read_u32().unwrap(), 0x34567890);
    assert_eq!(parcel.read_i32().unwrap(), -12345);
    let mut read_bytes = vec![0u8; 4];
    parcel.read_bytes(&mut read_bytes).unwrap();
    assert_eq!(read_bytes, vec![1, 2, 3, 4]);
}

#[test]
fn test_read_error_out_of_bounds() {
    let _guard = ut_registry_guard!();
    log_i!("test_read_error_out_of_bounds start");

    let mut parcel = Parcel::new();
    parcel.data = vec![1, 2, 3];
    parcel.read_pos = 2;

    let mut buffer = vec![0u8; 4];
    let result = parcel.read_bytes(&mut buffer);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), ErrorCode::ReadParcelError);
}

#[test]
fn test_read_u32_error_insufficient_data() {
    let _guard = ut_registry_guard!();
    log_i!("test_read_u32_error_insufficient_data start");

    let mut parcel = Parcel::new();
    parcel.data = vec![1, 2, 3]; // Only 3 bytes, need 4 for u32
    parcel.read_pos = 0;

    let result = parcel.read_u32();
    assert!(result.is_err());
}

#[test]
fn test_read_u64_error_insufficient_data() {
    let _guard = ut_registry_guard!();
    log_i!("test_read_u64_error_insufficient_data start");

    let mut parcel = Parcel::new();
    parcel.data = vec![1, 2, 3, 4, 5, 6, 7]; // Only 7 bytes, need 8 for u64
    parcel.read_pos = 0;

    let result = parcel.read_u64();
    assert!(result.is_err());
}

#[test]
fn test_default_trait() {
    let _guard = ut_registry_guard!();
    log_i!("test_default_trait start");

    let parcel = Parcel::default();
    assert_eq!(parcel.data.len(), 0);
    assert_eq!(parcel.read_pos, 0);
}

#[test]
fn test_partial_read() {
    let _guard = ut_registry_guard!();
    log_i!("test_partial_read start");

    let mut parcel = Parcel::new();
    let test_bytes = vec![10, 20, 30, 40, 50, 60, 70, 80];

    parcel.write_bytes(&test_bytes);

    parcel.read_pos = 2;
    let mut partial_buffer = vec![0u8; 3];
    parcel.read_bytes(&mut partial_buffer).unwrap();
    assert_eq!(partial_buffer, vec![30, 40, 50]);
}

#[test]
fn test_empty_parcel() {
    let _guard = ut_registry_guard!();
    log_i!("test_empty_parcel start");

    let parcel = Parcel::new();
    assert!(parcel.data.is_empty());
    assert_eq!(parcel.read_pos, 0);

    let mut empty_parcel = Parcel::new();
    let result = empty_parcel.read_u8();
    assert!(result.is_err());
}

#[test]
fn test_large_data() {
    let _guard = ut_registry_guard!();
    log_i!("test_large_data start");

    let mut parcel = Parcel::new();
    let large_data = vec![0xAAu8; 1024];

    parcel.write_bytes(&large_data);
    assert_eq!(parcel.data.len(), 1024);

    parcel.read_pos = 0;
    let mut read_data = vec![0u8; 1024];
    parcel.read_bytes(&mut read_data).unwrap();
    assert_eq!(read_data, large_data);
}

#[test]
fn test_boundary_conditions() {
    let _guard = ut_registry_guard!();
    log_i!("test_boundary_conditions start");

    let mut parcel = Parcel::new();

    // Test max values
    parcel.write_u8(u8::MAX);
    parcel.write_u32(u32::MAX);
    parcel.write_u64(u64::MAX);
    parcel.write_i8(i8::MAX);
    parcel.write_i32(i32::MAX);
    parcel.write_i64(i64::MAX);

    parcel.read_pos = 0;

    assert_eq!(parcel.read_u8().unwrap(), u8::MAX);
    assert_eq!(parcel.read_u32().unwrap(), u32::MAX);
    assert_eq!(parcel.read_u64().unwrap(), u64::MAX);
    assert_eq!(parcel.read_i8().unwrap(), i8::MAX);
    assert_eq!(parcel.read_i32().unwrap(), i32::MAX);
    assert_eq!(parcel.read_i64().unwrap(), i64::MAX);
}

#[test]
fn test_zero_values() {
    let _guard = ut_registry_guard!();
    log_i!("test_zero_values start");

    let mut parcel = Parcel::new();

    // Test zero values
    parcel.write_u8(0);
    parcel.write_u32(0);
    parcel.write_u64(0);
    parcel.write_i8(0);
    parcel.write_i32(0);
    parcel.write_i64(0);

    parcel.read_pos = 0;

    assert_eq!(parcel.read_u8().unwrap(), 0);
    assert_eq!(parcel.read_u32().unwrap(), 0);
    assert_eq!(parcel.read_u64().unwrap(), 0);
    assert_eq!(parcel.read_i8().unwrap(), 0);
    assert_eq!(parcel.read_i32().unwrap(), 0);
    assert_eq!(parcel.read_i64().unwrap(), 0);
}
