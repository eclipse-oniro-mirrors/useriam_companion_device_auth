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
use crate::String;
use crate::Vec;
use crate::{log_e, p};
use core::mem::size_of;

const DEFAULT_PARCEL_CAPACITY: usize = 4096;

#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct Parcel {
    data: Vec<u8>,
    read_pos: usize,
}

impl From<Vec<u8>> for Parcel {
    fn from(data: Vec<u8>) -> Self {
        Parcel { data, read_pos: 0 }
    }
}

impl From<&[u8]> for Parcel {
    fn from(data: &[u8]) -> Self {
        Parcel {
            data: data.to_vec(),
            read_pos: 0,
        }
    }
}

impl Parcel {
    pub fn new() -> Self {
        Parcel {
            data: Vec::with_capacity(DEFAULT_PARCEL_CAPACITY),
            read_pos: 0,
        }
    }

    pub fn has_next(&self) -> bool {
        self.read_pos < self.data.len()
    }

    pub fn write_u8(&mut self, value: u8) -> () {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_u16(&mut self, value: u16) -> () {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_u16_le(&mut self, value: u16) -> () {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) -> () {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_u32_le(&mut self, value: u32) -> () {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) -> () {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_i8(&mut self, value: i8) -> () {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_i32(&mut self, value: i32) -> () {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_i32_le(&mut self, value: i32) -> () {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn write_i64(&mut self, value: i64) -> () {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_bytes(&mut self, value: &[u8]) -> () {
        self.data.extend_from_slice(value);
    }

    pub fn write_string(&mut self, value: &str) -> () {
        let bytes = value.as_bytes();
        self.write_u32(bytes.len() as u32);
        self.write_bytes(bytes);
    }

    pub fn read_u8(&mut self) -> Result<u8, ErrorCode> {
        let mut buf = [0u8; size_of::<u8>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(u8::from_ne_bytes(buf))
    }

    pub fn read_u16(&mut self) -> Result<u16, ErrorCode> {
        let mut buf = [0u8; size_of::<u16>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(u16::from_ne_bytes(buf))
    }

    pub fn read_u16_le(&mut self) -> Result<u16, ErrorCode> {
        let mut buf = [0u8; size_of::<u16>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(u16::from_le_bytes(buf))
    }

    pub fn read_u32(&mut self) -> Result<u32, ErrorCode> {
        let mut buf = [0u8; size_of::<u32>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(u32::from_ne_bytes(buf))
    }

    pub fn read_u32_le(&mut self) -> Result<u32, ErrorCode> {
        let mut buf = [0u8; size_of::<u32>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_u64(&mut self) -> Result<u64, ErrorCode> {
        let mut buf = [0u8; size_of::<u64>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(u64::from_ne_bytes(buf))
    }

    pub fn read_i8(&mut self) -> Result<i8, ErrorCode> {
        let mut buf = [0u8; size_of::<i8>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(i8::from_ne_bytes(buf))
    }

    pub fn read_i32(&mut self) -> Result<i32, ErrorCode> {
        let mut buf = [0u8; size_of::<i32>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(i32::from_ne_bytes(buf))
    }

    pub fn read_i32_le(&mut self) -> Result<i32, ErrorCode> {
        let mut buf = [0u8; size_of::<i32>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(i32::from_le_bytes(buf))
    }

    pub fn read_i64(&mut self) -> Result<i64, ErrorCode> {
        let mut buf = [0u8; size_of::<i64>()];
        self.read_bytes(&mut buf).map_err(|e| p!(e))?;
        Ok(i64::from_ne_bytes(buf))
    }

    pub fn read_bytes(&mut self, value: &mut [u8]) -> Result<(), ErrorCode> {
        if self.read_pos.checked_add(value.len()).unwrap_or(usize::MAX) > self.data.len() {
            log_e!(
                "read bytes error, len: {}, read_pos: {}, value len: {}",
                self.data.len(),
                self.read_pos,
                value.len()
            );
            return Err(ErrorCode::ReadParcelError);
        }

        value.copy_from_slice(&self.data[self.read_pos..self.read_pos + value.len()]);
        self.read_pos += value.len();
        Ok(())
    }

    pub fn read_string(&mut self) -> Result<String, ErrorCode> {
        let len = self.read_u32().map_err(|e| p!(e))? as usize;
        if len > DEFAULT_PARCEL_CAPACITY {
            log_e!("string length too long: {}", len);
            return Err(ErrorCode::ReadParcelError);
        }

        if self.read_pos.checked_add(len).unwrap_or(usize::MAX) > self.data.len() {
            log_e!(
                "not enough data for string, need: {}, available: {}",
                len,
                self.data.len() - self.read_pos
            );
            return Err(ErrorCode::ReadParcelError);
        }

        let string_data = &self.data[self.read_pos..self.read_pos + len];
        self.read_pos += len;

        String::from_utf8(string_data.to_vec()).map_err(|e| {
            log_e!("utf8 decode error: {}", e);
            ErrorCode::ReadParcelError
        })
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Default for Parcel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::ErrorCode;

    #[test]
    fn test_parcel_new() {
        let parcel = Parcel::new();
        assert_eq!(parcel.data.len(), 0);
        assert_eq!(parcel.read_pos, 0);
    }

    #[test]
    fn test_parcel_from_vec() {
        let data = vec![1, 2, 3, 4, 5];
        let parcel = Parcel::from(data.clone());
        assert_eq!(parcel.data, data);
        assert_eq!(parcel.read_pos, 0);
    }

    #[test]
    fn test_write_read_u8() {
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
        let mut parcel = Parcel::new();
        let test_value: u32 = 0x12345678;

        parcel.write_u32_le(test_value);

        parcel.read_pos = 0;
        let read_value = parcel.read_u32_le().unwrap();
        assert_eq!(read_value, test_value);
    }

    #[test]
    fn test_write_read_u64() {
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
        let mut parcel = Parcel::new();
        let test_value: i8 = -42;

        parcel.write_i8(test_value);

        parcel.read_pos = 0;
        let read_value = parcel.read_i8().unwrap();
        assert_eq!(read_value, test_value);
    }

    #[test]
    fn test_write_read_i32() {
        let mut parcel = Parcel::new();
        let test_value: i32 = -123456789;

        parcel.write_i32(test_value);

        parcel.read_pos = 0;
        let read_value = parcel.read_i32().unwrap();
        assert_eq!(read_value, test_value);
    }

    #[test]
    fn test_write_read_i32_le() {
        let mut parcel = Parcel::new();
        let test_value: i32 = -12345;

        parcel.write_i32_le(test_value);

        parcel.read_pos = 0;
        let read_value = parcel.read_i32_le().unwrap();
        assert_eq!(read_value, test_value);
    }

    #[test]
    fn test_write_read_i64() {
        let mut parcel = Parcel::new();
        let test_value: i64 = -1234567890123456789;

        parcel.write_i64(test_value);

        parcel.read_pos = 0;
        let read_value = parcel.read_i64().unwrap();
        assert_eq!(read_value, test_value);
    }

    #[test]
    fn test_write_read_bytes() {
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
        let mut parcel = Parcel::new();
        parcel.data = vec![1, 2, 3]; // Only 3 bytes, need 4 for u32
        parcel.read_pos = 0;

        let result = parcel.read_u32();
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u64_error_insufficient_data() {
        let mut parcel = Parcel::new();
        parcel.data = vec![1, 2, 3, 4, 5, 6, 7]; // Only 7 bytes, need 8 for u64
        parcel.read_pos = 0;

        let result = parcel.read_u64();
        assert!(result.is_err());
    }

    #[test]
    fn test_default_trait() {
        let parcel = Parcel::default();
        assert_eq!(parcel.data.len(), 0);
        assert_eq!(parcel.read_pos, 0);
    }

    #[test]
    fn test_partial_read() {
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
        let parcel = Parcel::new();
        assert!(parcel.data.is_empty());
        assert_eq!(parcel.read_pos, 0);

        let mut empty_parcel = Parcel::new();
        let result = empty_parcel.read_u8();
        assert!(result.is_err());
    }

    #[test]
    fn test_large_data() {
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
}
