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

use crate::common::constants::*;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::utils::message_codec::MessageCodec;
use crate::utils::message_codec::MessageSignParam;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct FwkIssueTokenRequest {
    pub property_mode: u32,
    pub auth_type: u32,
    pub atl: i32,
    pub template_ids: Vec<u64>,
}

impl FwkIssueTokenRequest {
    pub fn decode(fwk_message: &[u8]) -> Result<Box<Self>, ErrorCode> {
        let pub_key = MiscManagerRegistry::get_mut().get_fwk_pub_key().map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
        let attribute = message_codec.deserialize_attribute(fwk_message).map_err(|e| p!(e))?;
        let property_mode = attribute.get_u32(AttributeKey::AttrPropertyMode).map_err(|e| p!(e))?;
        let auth_type = attribute.get_u32(AttributeKey::AttrType).map_err(|e| p!(e))?;
        let atl = attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;
        let template_ids = attribute.get_u64_vec(AttributeKey::AttrTemplateIdList).map_err(|e| p!(e))?;

        Ok(Box::new(FwkIssueTokenRequest { property_mode, auth_type, atl, template_ids }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecPreIssueRequest {
    pub salt: [u8; HKDF_SALT_SIZE],
}

impl SecPreIssueRequest {
    pub fn decode(message: &[u8], device_type: DeviceType) -> Result<Box<Self>, ErrorCode> {
        let message_type = AttributeKey::try_from(device_type).map_err(|e| p!(e))?;
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(message_type).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let salt_slice = message_attribute.get_u8_slice(AttributeKey::AttrSalt).map_err(|e| p!(e))?;
        Ok(Box::new(Self {
            salt: salt_slice.try_into().map_err(|e| {
                log_e!("try_into fail: {:?}", e);
                ErrorCode::GeneralError
            })?,
        }))
    }

    pub fn encode(&self, device_type: DeviceType) -> Result<Vec<u8>, ErrorCode> {
        let message_type = AttributeKey::try_from(device_type).map_err(|e| p!(e))?;
        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(message_type, attribute.to_bytes()?.as_slice());
        final_attribute.to_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecIssueTokenReply {
    pub result: i32,
}

impl SecIssueTokenReply {
    pub fn decode(message: &[u8], device_type: DeviceType) -> Result<Box<Self>, ErrorCode> {
        let message_type = AttributeKey::try_from(device_type).map_err(|e| p!(e))?;
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(message_type).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let result = message_attribute.get_i32(AttributeKey::AttrResultCode).map_err(|e| p!(e))?;

        Ok(Box::new(Self { result }))
    }

    pub fn encode(&self, device_type: DeviceType) -> Result<Vec<u8>, ErrorCode> {
        let message_type = AttributeKey::try_from(device_type).map_err(|e| p!(e))?;
        let mut attribute = Attribute::new();
        attribute.set_i32(AttributeKey::AttrResultCode, 0);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(message_type, attribute.to_bytes()?.as_slice());
        final_attribute.to_bytes()
    }
}
