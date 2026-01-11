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
use crate::{log_e, log_i, p, Vec};
extern crate alloc;
use crate::utils::parcel::Parcel;
use crate::String;
use alloc::{collections::BTreeMap, vec};
use core::mem;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord)]
#[repr(i32)]
pub enum AttributeKey {
    AttrRoot = 100000,
    AttrResultCode = 100001,
    AttrSignature = 100004,
    AttrTemplateId = 100006,
    AttrTemplateIdList = 100007,
    AttrRemainAttempts = 100009,
    AttrLockoutDuration = 100010,
    AttrScheduleId = 100014,
    AttrData = 100020,
    AttrPinSubType = 100021,
    AttrPropertyMode = 100023,
    AttrType = 100024,
    AttrCapabilityLevel = 100029,
    AttrUserId = 100041,
    AttrToken = 100042,
    AttrEsl = 100044,
    AttrPublicKey = 100065,
    AttrChallenge = 100066,
    AttrAuthTrustLevel = 100089,

    AttrMessage = 300001,
    AttrProtocolList = 300002,
    AttrAlgoList = 300003,
    AttrCapabilityList = 300004,
    AttrDeviceId = 300005,
    AttrSalt = 300006,
    AttrTag = 300007,
    AttrIv = 300008,
    AttrEncryptData = 300009,
    AttrTrackAbilityLevel = 300010,
    AttrHmac = 300011,
}

impl TryFrom<i32> for AttributeKey {
    type Error = ErrorCode;
    fn try_from(value: i32) -> Result<Self, ErrorCode> {
        match value {
            100000 => Ok(AttributeKey::AttrRoot),
            100001 => Ok(AttributeKey::AttrResultCode),
            100004 => Ok(AttributeKey::AttrSignature),
            100006 => Ok(AttributeKey::AttrTemplateId),
            100007 => Ok(AttributeKey::AttrTemplateIdList),
            100009 => Ok(AttributeKey::AttrRemainAttempts),
            100010 => Ok(AttributeKey::AttrLockoutDuration),
            100014 => Ok(AttributeKey::AttrScheduleId),
            100020 => Ok(AttributeKey::AttrData),
            100021 => Ok(AttributeKey::AttrPinSubType),
            100023 => Ok(AttributeKey::AttrPropertyMode),
            100024 => Ok(AttributeKey::AttrType),
            100029 => Ok(AttributeKey::AttrCapabilityLevel),
            100041 => Ok(AttributeKey::AttrUserId),
            100042 => Ok(AttributeKey::AttrToken),
            100044 => Ok(AttributeKey::AttrEsl),
            100065 => Ok(AttributeKey::AttrPublicKey),
            100066 => Ok(AttributeKey::AttrChallenge),
            100089 => Ok(AttributeKey::AttrAuthTrustLevel),
            300001 => Ok(AttributeKey::AttrMessage),
            300002 => Ok(AttributeKey::AttrProtocolList),
            300003 => Ok(AttributeKey::AttrAlgoList),
            300004 => Ok(AttributeKey::AttrCapabilityList),
            300005 => Ok(AttributeKey::AttrDeviceId),
            300006 => Ok(AttributeKey::AttrSalt),
            300007 => Ok(AttributeKey::AttrTag),
            300008 => Ok(AttributeKey::AttrIv),
            300009 => Ok(AttributeKey::AttrEncryptData),
            300010 => Ok(AttributeKey::AttrTrackAbilityLevel),
            300011 => Ok(AttributeKey::AttrHmac),
            _ => Err(ErrorCode::GeneralError),
        }
    }
}

pub const MAX_SUB_MSG_NUM: usize = 10;
pub const MAX_EXECUTOR_MSG_LEN: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    map: BTreeMap<AttributeKey, Vec<u8>>,
}

impl Attribute {
    pub fn new() -> Self {
        Attribute { map: BTreeMap::new() }
    }

    pub fn try_from_bytes(msg: &[u8]) -> Result<Self, ErrorCode> {
        if msg.is_empty() {
            log_e!("msg is empty");
            return Err(ErrorCode::BadParam);
        }

        let mut attribute = Attribute::new();
        let mut parcel = Parcel::from(msg);

        while parcel.has_next() {
            let attr_key = parcel.read_i32_le().map_err(|e| p!(e))?;
            let length = parcel.read_u32_le().map_err(|e| p!(e))? as usize;

            let mut data = vec![0u8; length];
            parcel.read_bytes(&mut data).map_err(|e| p!(e))?;

            match AttributeKey::try_from(attr_key) {
                Ok(key) => {
                    attribute.map.insert(key, data);
                },
                Err(_) => {
                    log_i!(" attribute {} not defined, skip", attr_key);
                },
            }
        }

        Ok(attribute)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorCode> {
        let mut parcel = Parcel::new();

        for (&key, data) in &self.map {
            parcel.write_i32_le(key as i32);
            parcel.write_u32_le(data.len() as u32);
            parcel.write_bytes(data);
        }

        Ok(parcel.into_vec())
    }

    pub fn get_u16(&self, key: AttributeKey) -> Result<u16, ErrorCode> {
        let data = self.get_u8_slice(key).map_err(|e| p!(e))?;
        if data.len() != mem::size_of::<u16>() {
            log_e!("Invalid data size");
            return Err(ErrorCode::GeneralError);
        }

        Ok(u16::from_le_bytes(data.try_into().unwrap()))
    }

    pub fn set_u16(&mut self, key: AttributeKey, value: u16) {
        self.map.insert(key, value.to_le_bytes().to_vec());
    }

    pub fn get_u32(&self, key: AttributeKey) -> Result<u32, ErrorCode> {
        let data = self.get_u8_slice(key).map_err(|e| p!(e))?;
        if data.len() != mem::size_of::<u32>() {
            log_e!("Invalid data size");
            return Err(ErrorCode::GeneralError);
        }

        Ok(u32::from_le_bytes(data.try_into().unwrap()))
    }

    pub fn set_u32(&mut self, key: AttributeKey, value: u32) {
        self.map.insert(key, value.to_le_bytes().to_vec());
    }

    pub fn get_i32(&self, key: AttributeKey) -> Result<i32, ErrorCode> {
        let data = self.get_u8_slice(key).map_err(|e| p!(e))?;
        if data.len() != mem::size_of::<i32>() {
            log_e!("Invalid data size");
            return Err(ErrorCode::GeneralError);
        }

        Ok(i32::from_le_bytes(data.try_into().unwrap()))
    }

    pub fn set_i32(&mut self, key: AttributeKey, value: i32) {
        self.map.insert(key, value.to_le_bytes().to_vec());
    }

    pub fn get_u64(&self, key: AttributeKey) -> Result<u64, ErrorCode> {
        let data = self.get_u8_slice(key).map_err(|e| p!(e))?;
        if data.len() != mem::size_of::<u64>() {
            log_e!("Invalid data size");
            return Err(ErrorCode::GeneralError);
        }

        Ok(u64::from_le_bytes(data.try_into().unwrap()))
    }

    pub fn set_u64(&mut self, key: AttributeKey, value: u64) {
        self.map.insert(key, value.to_le_bytes().to_vec());
    }

    pub fn get_u8_slice(&self, key: AttributeKey) -> Result<&[u8], ErrorCode> {
        self.map.get(&key).map(|val| val.as_slice()).ok_or_else(|| {
            log_e!("Attribute is not set, key:{:?}", key);
            ErrorCode::GeneralError
        })
    }

    pub fn fill_u8_slice(&self, key: AttributeKey, buffer: &mut [u8]) -> Result<(), ErrorCode> {
        let value = self.map.get(&key).map(|val| val.as_slice()).ok_or_else(|| {
            log_e!("Attribute is not set, key:{:?}", key);
            ErrorCode::GeneralError
        })?;

        if value.len() != buffer.len() {
            log_e!("Attribute size is unexpected, expected {} actual {}", buffer.len(), value.len());
            return Err(ErrorCode::GeneralError);
        }

        buffer.copy_from_slice(value);
        Ok(())
    }

    pub fn get_u8_vec(&self, key: AttributeKey) -> Result<&Vec<u8>, ErrorCode> {
        self.map.get(&key).ok_or_else(|| {
            log_e!("Attribute is not set, key:{:?}", key);
            ErrorCode::GeneralError
        })
    }

    pub fn set_u8_slice(&mut self, key: AttributeKey, data: &[u8]) {
        self.map.insert(key, data.to_vec());
    }

    pub fn get_u64_vec(&self, key: AttributeKey) -> Result<Vec<u64>, ErrorCode> {
        let data = self.get_u8_slice(key).map_err(|e| p!(e))?;
        let chunks = data.chunks_exact(mem::size_of::<u64>());
        if chunks.remainder().len() != 0 {
            log_e!("u8 slice length {} is incorrect", data.len());
            return Err(ErrorCode::GeneralError);
        }

        let mut u64_vec = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            u64_vec.push(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        Ok(u64_vec)
    }

    pub fn set_u64_slice(&mut self, key: AttributeKey, data: &[u64]) -> () {
        let mut bytes = Vec::with_capacity(data.len() * mem::size_of::<u64>());
        for &value in data {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        self.map.insert(key, bytes);
    }

    pub fn get_u16_vec(&self, key: AttributeKey) -> Result<Vec<u16>, ErrorCode> {
        let data = self.get_u8_slice(key).map_err(|e| p!(e))?;
        let chunks = data.chunks_exact(mem::size_of::<u16>());
        if chunks.remainder().len() != 0 {
            log_e!("u8 slice length {} is incorrect", data.len());
            return Err(ErrorCode::GeneralError);
        }

        let mut u16_vec = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            u16_vec.push(u16::from_le_bytes(chunk.try_into().unwrap()));
        }
        Ok(u16_vec)
    }

    pub fn set_u16_slice(&mut self, key: AttributeKey, data: &[u16]) -> () {
        let mut bytes = Vec::with_capacity(data.len() * mem::size_of::<u16>());
        for &value in data {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        self.map.insert(key, bytes);
    }

    pub fn get_u8_vecs(&self, key: AttributeKey) -> Result<Vec<Vec<u8>>, ErrorCode> {
        let mut parcel = Parcel::from(self.map.get(&key).map(|val| val.as_slice()).ok_or_else(|| {
            log_e!("Attribute is not set, key:{:?}", key);
            ErrorCode::GeneralError
        })?);
        let mut u8_vecs = Vec::new();
        while parcel.has_next() {
            let length = parcel.read_u32_le().map_err(|e| p!(e))? as usize;
            let mut data = vec![0u8; length];
            parcel.read_bytes(&mut data).map_err(|e| p!(e))?;
            u8_vecs.push(data);
        }
        Ok(u8_vecs)
    }

    pub fn set_u8_slices(&mut self, key: AttributeKey, u8_slices: &[&[u8]]) -> () {
        let mut parcel = Parcel::new();
        for &slice in u8_slices {
            parcel.write_u32_le(slice.len() as u32);
            parcel.write_bytes(slice);
        }
        self.map.insert(key, parcel.into_vec());
    }

    pub fn get_string(&self, key: AttributeKey) -> Result<String, ErrorCode> {
        let data = self.get_u8_slice(key).map_err(|e| p!(e))?;
        String::from_utf8(data.to_vec()).map_err(|e| {
            log_e!("Failed to convert bytes to string for key {:?}: {:?}", key, e);
            ErrorCode::GeneralError
        })
    }

    pub fn set_string(&mut self, key: AttributeKey, value: String) {
        self.map.insert(key, value.into_bytes());
    }
}
