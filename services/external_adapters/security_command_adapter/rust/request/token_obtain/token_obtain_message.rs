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

use crate::common::constants::{ErrorCode, ProcessorType, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE, HKDF_SALT_SIZE};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::utils::message_codec::MessageCodec;
use crate::utils::message_codec::MessageSignParam;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, p, Box, Vec};
use crate::traits::log_trace::RustFileId;
pub(crate) const FILE_ID: u16 = RustFileId::TOKEN_OBTAIN_MESSAGE as u16;
#[derive(Debug, Clone, PartialEq)]
pub struct FwkObtainTokenRequest {
    pub property_mode: u32,
    pub auth_type: u32,
    pub atl: i32,
}

impl FwkObtainTokenRequest {
    pub fn decode(fwk_message: &[u8]) -> Result<Box<Self>, ErrorCode> {
        let pub_key = MiscManagerRegistry::get_mut().get_fwk_pub_key().map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
        let attribute = message_codec.deserialize_attribute(fwk_message).map_err(|e| p!(e))?;
        let property_mode = attribute.get_u32(AttributeKey::AttrPropertyMode).map_err(|e| p!(e))?;
        let auth_type = attribute.get_u32(AttributeKey::AttrType).map_err(|e| p!(e))?;
        let atl = attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;

        Ok(Box::new(FwkObtainTokenRequest { property_mode, auth_type, atl }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecPreObtainTokenRequest {
    pub salt: [u8; HKDF_SALT_SIZE],
    pub challenge: u64,
}

impl SecPreObtainTokenRequest {
    pub fn decode(message: &[u8], processor_type: ProcessorType) -> Result<Box<Self>, ErrorCode> {
        let message_type = AttributeKey::try_from(processor_type).map_err(|e| p!(e))?;
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(message_type).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let salt_slice = message_attribute.get_u8_slice(AttributeKey::AttrSalt).map_err(|e| p!(e))?;
        let challenge = message_attribute.get_u64(AttributeKey::AttrHostChallenge).map_err(|e| p!(e))?;
        Ok(Box::new(Self {
            salt: salt_slice.try_into().map_err(|e| {
                log_e!("try_into fail: {:?}", e);
                ErrorCode::GeneralError
            })?,
            challenge,
        }))
    }

    pub fn encode(&self, processor_type: ProcessorType) -> Result<Vec<u8>, ErrorCode> {
        let message_type = AttributeKey::try_from(processor_type).map_err(|e| p!(e))?;
        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);
        attribute.set_u64(AttributeKey::AttrHostChallenge, self.challenge);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(message_type, attribute.to_bytes()?.as_slice());
        final_attribute.to_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecPreObtainTokenReply {
    pub challenge: u64,
    pub tag: [u8; AES_GCM_TAG_SIZE],
    pub iv: [u8; AES_GCM_IV_SIZE],
    pub encrypt_data: Vec<u8>,
}

impl SecPreObtainTokenReply {
    pub fn decode(message: &[u8], processor_type: ProcessorType) -> Result<Box<Self>, ErrorCode> {
        let message_type = AttributeKey::try_from(processor_type).map_err(|e| p!(e))?;
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(message_type).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let challenge = message_attribute.get_u64(AttributeKey::AttrCompanionChallenge).map_err(|e| p!(e))?;
        let tag_slice = message_attribute.get_u8_slice(AttributeKey::AttrTag).map_err(|e| p!(e))?;
        let iv_slice = message_attribute.get_u8_slice(AttributeKey::AttrIv).map_err(|e| p!(e))?;
        let encrypt_data_slice = message_attribute.get_u8_slice(AttributeKey::AttrEncryptData).map_err(|e| p!(e))?;
        Ok(Box::new(Self {
            challenge,
            tag: tag_slice.try_into().map_err(|e| {
                log_e!("try_into fail: {:?}", e);
                ErrorCode::GeneralError
            })?,
            iv: iv_slice.try_into().map_err(|e| {
                log_e!("try_into fail: {:?}", e);
                ErrorCode::GeneralError
            })?,
            encrypt_data: encrypt_data_slice.to_vec(),
        }))
    }

    pub fn encode(&self, processor_type: ProcessorType) -> Result<Vec<u8>, ErrorCode> {
        let message_type = AttributeKey::try_from(processor_type).map_err(|e| p!(e))?;
        let mut attribute = Attribute::new();
        attribute.set_u64(AttributeKey::AttrCompanionChallenge, self.challenge);
        attribute.set_u8_slice(AttributeKey::AttrTag, &self.tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &self.iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &self.encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(message_type, attribute.to_bytes()?.as_slice());
        final_attribute.to_bytes()
    }
}
