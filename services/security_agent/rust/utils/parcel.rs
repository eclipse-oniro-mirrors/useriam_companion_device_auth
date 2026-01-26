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

pub struct Parcel {
    pub data: Vec<u8>,
    pub read_pos: usize,
}

impl From<Vec<u8>> for Parcel {
    fn from(data: Vec<u8>) -> Self {
        Parcel { data, read_pos: 0 }
    }
}

impl From<&[u8]> for Parcel {
    fn from(data: &[u8]) -> Self {
        Parcel { data: data.to_vec(), read_pos: 0 }
    }
}

impl Parcel {
    pub fn new() -> Self {
        Parcel { data: Vec::with_capacity(DEFAULT_PARCEL_CAPACITY), read_pos: 0 }
    }

    pub fn has_next(&self) -> bool {
        self.read_pos < self.data.len()
    }

    pub fn write_u8(&mut self, value: u8) {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_u16_le(&mut self, value: u16) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_u32_le(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_i8(&mut self, value: i8) {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_i32(&mut self, value: i32) {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_i32_le(&mut self, value: i32) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn write_i64(&mut self, value: i64) {
        self.write_bytes(&value.to_ne_bytes());
    }

    pub fn write_bytes(&mut self, value: &[u8]) {
        self.data.extend_from_slice(value);
    }

    pub fn write_string(&mut self, value: &str) {
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
            log_e!("not enough data for string, need: {}, available: {}", len, self.data.len() - self.read_pos);
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
