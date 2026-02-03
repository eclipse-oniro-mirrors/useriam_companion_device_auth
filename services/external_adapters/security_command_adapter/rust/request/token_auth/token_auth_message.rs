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
pub struct FwkAuthRequest {
    pub schedule_id: u64,
    pub template_ids: Vec<u64>,
    pub atl: i32,
}

impl FwkAuthRequest {
    pub fn decode(fwk_message: &[u8]) -> Result<Box<Self>, ErrorCode> {
        let pub_key = MiscManagerRegistry::get_mut().get_fwk_pub_key().map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
        let attribute = message_codec.deserialize_attribute(fwk_message).map_err(|e| p!(e))?;

        let schedule_id = attribute.get_u64(AttributeKey::AttrScheduleId).map_err(|e| p!(e))?;
        let template_ids = attribute.get_u64_vec(AttributeKey::AttrTemplateIdList).map_err(|e| p!(e))?;
        let atl = attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;

        Ok(Box::new(FwkAuthRequest { schedule_id, template_ids, atl }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FwkAuthReply {
    pub schedule_id: u64,
    pub template_id: u64,
    pub result_code: i32,
    pub acl: i32,
    pub pin_sub_type: u64,
    pub remain_attempts: i32,
    pub lock_duration: i32,
}

impl FwkAuthReply {
    pub fn encode(&self) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u64(AttributeKey::AttrScheduleId, self.schedule_id);
        attribute.set_i32(AttributeKey::AttrResultCode, self.result_code);
        attribute.set_i32(AttributeKey::AttrCapabilityLevel, self.acl);
        attribute.set_u64(AttributeKey::AttrTemplateId, self.template_id);
        attribute.set_u64(AttributeKey::AttrPinSubType, self.pin_sub_type);
        attribute.set_i32(AttributeKey::AttrRemainAttempts, self.remain_attempts);
        attribute.set_i32(AttributeKey::AttrLockoutDuration, self.lock_duration);

        let local_key_pair = MiscManagerRegistry::get_mut().get_local_key_pair().map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Executor(local_key_pair));
        let fwk_message = message_codec.serialize_attribute(&attribute).map_err(|e| p!(e))?;
        Ok(fwk_message)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecAuthReply {
    pub hmac: Vec<u8>,
}

impl SecAuthReply {
    pub fn decode(message: &[u8], device_type: DeviceType) -> Result<Box<Self>, ErrorCode> {
        let message_type = AttributeKey::try_from(device_type).map_err(|e| p!(e))?;
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(message_type).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let hmac = message_attribute.get_u8_slice(AttributeKey::AttrHmac).map_err(|e| p!(e))?;

        Ok(Box::new(Self { hmac: hmac.to_vec() }))
    }

    pub fn encode(&self, device_type: DeviceType) -> Result<Vec<u8>, ErrorCode> {
        let message_type = AttributeKey::try_from(device_type).map_err(|e| p!(e))?;
        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrHmac, &self.hmac);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(message_type, attribute.to_bytes()?.as_slice());
        final_attribute.to_bytes()
    }
}
