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
#[cfg(feature = "test-utils")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
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
    AttrProtocalList = 300002,
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
            300002 => Ok(AttributeKey::AttrProtocalList),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_key_test() {
        assert_eq!(AttributeKey::try_from(100000).unwrap(), AttributeKey::AttrRoot);
        assert_eq!(AttributeKey::try_from(100001).unwrap(), AttributeKey::AttrResultCode);
        assert_eq!(AttributeKey::try_from(100004).unwrap(), AttributeKey::AttrSignature);
        assert_eq!(AttributeKey::try_from(100006).unwrap(), AttributeKey::AttrTemplateId);
        assert_eq!(AttributeKey::try_from(100007).unwrap(), AttributeKey::AttrTemplateIdList);
        assert_eq!(AttributeKey::try_from(100009).unwrap(), AttributeKey::AttrRemainAttempts);
        assert_eq!(AttributeKey::try_from(100010).unwrap(), AttributeKey::AttrLockoutDuration);
        assert_eq!(AttributeKey::try_from(100014).unwrap(), AttributeKey::AttrScheduleId);
        assert_eq!(AttributeKey::try_from(100020).unwrap(), AttributeKey::AttrData);
        assert_eq!(AttributeKey::try_from(100021).unwrap(), AttributeKey::AttrPinSubType);
        assert_eq!(AttributeKey::try_from(100023).unwrap(), AttributeKey::AttrPropertyMode);
        assert_eq!(AttributeKey::try_from(100024).unwrap(), AttributeKey::AttrType);
        assert_eq!(AttributeKey::try_from(100029).unwrap(), AttributeKey::AttrCapabilityLevel);
        assert_eq!(AttributeKey::try_from(100041).unwrap(), AttributeKey::AttrUserId);
        assert_eq!(AttributeKey::try_from(100042).unwrap(), AttributeKey::AttrToken);
        assert_eq!(AttributeKey::try_from(100044).unwrap(), AttributeKey::AttrEsl);
        assert_eq!(AttributeKey::try_from(100065).unwrap(), AttributeKey::AttrPublicKey);
        assert_eq!(AttributeKey::try_from(100066).unwrap(), AttributeKey::AttrChallenge);
        assert_eq!(AttributeKey::try_from(100089).unwrap(), AttributeKey::AttrAuthTrustLevel);
        assert_eq!(AttributeKey::try_from(300001).unwrap(), AttributeKey::AttrMessage);
        assert_eq!(AttributeKey::try_from(300002).unwrap(), AttributeKey::AttrAlgoList);
        assert_eq!(AttributeKey::try_from(300003).unwrap(), AttributeKey::AttrCapabilityList);
        assert_eq!(AttributeKey::try_from(300004).unwrap(), AttributeKey::AttrDeviceId);
        assert_eq!(AttributeKey::try_from(300005).unwrap(), AttributeKey::AttrSalt);
        assert_eq!(AttributeKey::try_from(300006).unwrap(), AttributeKey::AttrTag);
        assert_eq!(AttributeKey::try_from(300007).unwrap(), AttributeKey::AttrIv);
        assert_eq!(AttributeKey::try_from(300008).unwrap(), AttributeKey::AttrEncryptData);
        assert_eq!(AttributeKey::try_from(300009).unwrap(), AttributeKey::AttrTrackAbilityLevel);
        assert_eq!(AttributeKey::try_from(300010).unwrap(), AttributeKey::AttrHmac);
        assert_eq!(AttributeKey::try_from(0), Err(ErrorCode::GeneralError));
    }

    #[test]
    fn try_from_bytes_fail_test() {
        assert_eq!(Attribute::try_from_bytes(&[]), Err(ErrorCode::BadParam));
        let mut parcel = Parcel::new();
        assert_eq!(Attribute::try_from_bytes(parcel.as_slice()), Err(ErrorCode::ReadParcelError));
        parcel.write_i32_le(0);
        assert_eq!(Attribute::try_from_bytes(parcel.as_slice()), Err(ErrorCode::ReadParcelError));
        parcel.write_u32_le(4);
        assert_eq!(Attribute::try_from_bytes(parcel.as_slice()), Err(ErrorCode::ReadParcelError));
        parcel.write_bytes(&[1, 2, 3, 4]);
        assert!(Attribute::try_from_bytes(parcel.as_slice()).is_ok());
    }

    #[test]
    fn try_from_bytes_success_test() {
        let mut parcel = Parcel::new();
        parcel.write_i32_le(AttributeKey::AttrRoot as i32);
        parcel.write_u32_le(4);
        parcel.write_bytes(&[1, 2, 3, 4]);
        assert!(Attribute::try_from_bytes(parcel.as_slice()).is_ok());
    }

    #[test]
    fn to_bytes_test() {
        let mut attribute = Attribute::new();
        attribute.set_u32(AttributeKey::AttrResultCode, 0);
        assert!(attribute.to_bytes().is_ok());
    }

    #[test]
    fn u16_test() {
        let mut attribute = Attribute::new();
        assert_eq!(attribute.get_u16(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
        attribute.set_u32(AttributeKey::AttrResultCode, 0);
        assert_eq!(attribute.get_u16(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
        attribute.set_u16(AttributeKey::AttrResultCode, 0);
        assert!(attribute.get_u16(AttributeKey::AttrResultCode).is_ok());
    }

    #[test]
    fn u32_test() {
        let mut attribute = Attribute::new();
        assert_eq!(attribute.get_u32(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
        attribute.set_u16(AttributeKey::AttrResultCode, 0);
        assert_eq!(attribute.get_u32(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
        attribute.set_u32(AttributeKey::AttrResultCode, 0);
        assert!(attribute.get_u32(AttributeKey::AttrResultCode).is_ok());
    }

    #[test]
    fn i32_test() {
        let mut attribute = Attribute::new();
        assert_eq!(attribute.get_i32(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
        attribute.set_u16(AttributeKey::AttrResultCode, 0);
        assert_eq!(attribute.get_i32(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
        attribute.set_i32(AttributeKey::AttrResultCode, 0);
        assert!(attribute.get_i32(AttributeKey::AttrResultCode).is_ok());
    }

    #[test]
    fn u64_test() {
        let mut attribute = Attribute::new();
        assert_eq!(attribute.get_u64(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
        attribute.set_u16(AttributeKey::AttrResultCode, 0);
        assert_eq!(attribute.get_u64(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
        attribute.set_u64(AttributeKey::AttrResultCode, 0);
        assert!(attribute.get_u64(AttributeKey::AttrResultCode).is_ok());
    }

    #[test]
    fn u8_slice_test() {
        let mut attribute: Attribute = Attribute::new();
        assert_eq!(attribute.get_u8_slice(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
        assert_eq!(attribute.get_u8_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

        assert_eq!(attribute.fill_u8_slice(AttributeKey::AttrResultCode, &mut [0u8; 0]), Err(ErrorCode::GeneralError));
        attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 1]);
        assert_eq!(attribute.fill_u8_slice(AttributeKey::AttrResultCode, &mut [0u8; 0]), Err(ErrorCode::GeneralError));
        assert!(attribute.fill_u8_slice(AttributeKey::AttrResultCode, &mut [0u8; 1]).is_ok());

        assert!(attribute.get_u8_slice(AttributeKey::AttrResultCode).is_ok());
        assert!(attribute.get_u8_vec(AttributeKey::AttrResultCode).is_ok());
    }

    #[test]
    fn u64_slice_test() {
        let mut attribute: Attribute = Attribute::new();
        assert_eq!(attribute.get_u64_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

        attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 1]);
        assert_eq!(attribute.get_u64_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

        attribute.set_u64_slice(AttributeKey::AttrResultCode, &[0u64; 1]);
        assert!(attribute.get_u64_vec(AttributeKey::AttrResultCode).is_ok());
    }

    #[test]
    fn u16_slice_test() {
        let mut attribute: Attribute = Attribute::new();
        assert_eq!(attribute.get_u16_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

        attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 1]);
        assert_eq!(attribute.get_u16_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

        attribute.set_u16_slice(AttributeKey::AttrResultCode, &[0u16; 1]);
        assert!(attribute.get_u16_vec(AttributeKey::AttrResultCode).is_ok());
    }

    #[test]
    fn u8_slices_test() {
        let mut attribute: Attribute = Attribute::new();
        assert_eq!(attribute.get_u8_vecs(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

        attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 1]);
        assert_eq!(attribute.get_u8_vecs(AttributeKey::AttrResultCode), Err(ErrorCode::ReadParcelError));
        attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 4]);
        assert_eq!(attribute.get_u8_vecs(AttributeKey::AttrResultCode), Err(ErrorCode::ReadParcelError));

        attribute.set_u8_slices(AttributeKey::AttrResultCode, &[&[0u8]]);
        assert!(attribute.get_u8_vecs(AttributeKey::AttrResultCode).is_ok());
    }

    #[test]
    fn string_test() {
        let mut attribute: Attribute = Attribute::new();
        assert_eq!(attribute.get_string(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

        let sparkle_heart = [0u8, 159u8, 146u8, 150u8];
        attribute.set_u8_slice(AttributeKey::AttrResultCode, &sparkle_heart);
        assert_eq!(attribute.get_string(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

        attribute.set_string(AttributeKey::AttrResultCode, String::from("Hello"));
        assert!(attribute.get_string(AttributeKey::AttrResultCode).is_ok());
    }
}
