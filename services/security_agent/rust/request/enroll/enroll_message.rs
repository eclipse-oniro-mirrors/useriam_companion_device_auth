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
use crate::common::types::*;
use crate::jobs::companion_db_helper;
use crate::jobs::host_db_helper;
use crate::jobs::message_crypto;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::utils::message_codec::MessageCodec;
use crate::utils::message_codec::MessageSignParam;
use crate::utils::{Attribute, AttributeKey};
use crate::String;
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct FwkEnrollRequest {
    pub schedule_id: u64,
    pub atl: i32,
}

impl FwkEnrollRequest {
    pub fn decode(fwk_message: &[u8]) -> Result<Self, ErrorCode> {
        let pub_key = MiscManagerRegistry::get_mut().get_fwk_pub_key().map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
        let attribute = message_codec.deserialize_attribute(fwk_message).map_err(|e| p!(e))?;

        let schedule_id = attribute.get_u64(AttributeKey::AttrScheduleId).map_err(|e| p!(e))?;
        let atl = attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;
        Ok(FwkEnrollRequest { schedule_id, atl })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FwkEnrollReply {
    pub schedule_id: u64,
    pub template_id: u64,
    pub result_code: i32,
    pub acl: u32,
    pub pin_sub_type: u64,
    pub remain_attempts: i32,
    pub lock_duration: i32,
}

impl FwkEnrollReply {
    pub fn encode(&self) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u64(AttributeKey::AttrScheduleId, self.schedule_id);
        attribute.set_i32(AttributeKey::AttrResultCode, self.result_code);
        attribute.set_u32(AttributeKey::AttrCapabilityLevel, self.acl);
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
pub struct SecKeyNegoRequest {
    pub algorithm_list: Vec<u16>,
}

impl SecKeyNegoRequest {
    pub fn encode(&self, _device_type: DeviceType) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u16_slice(AttributeKey::AttrAlgoList, &self.algorithm_list);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        Ok(final_attribute.to_bytes()?)
    }

    pub fn decode(message: &[u8], _device_type: DeviceType) -> Result<Self, ErrorCode> {
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(AttributeKey::AttrMessage).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;

        let algorithm_list = message_attribute.get_u16_vec(AttributeKey::AttrAlgoList).map_err(|e| p!(e))?;

        Ok(Self { algorithm_list: algorithm_list.to_vec() })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecKeyNegoReply {
    pub algorithm: u16,
    pub challenge: u64,
    pub pub_key: Vec<u8>,
}

impl SecKeyNegoReply {
    pub fn encode(&self, _device_type: DeviceType) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u16(AttributeKey::AttrAlgoList, self.algorithm);
        attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);
        attribute.set_u8_slice(AttributeKey::AttrPublicKey, &self.pub_key);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());

        Ok(final_attribute.to_bytes()?)
    }

    pub fn decode(message: &[u8], _device_type: DeviceType) -> Result<Self, ErrorCode> {
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(AttributeKey::AttrMessage).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;

        let algorithm = message_attribute.get_u16(AttributeKey::AttrAlgoList).map_err(|e| p!(e))?;

        let challenge = message_attribute.get_u64(AttributeKey::AttrChallenge).map_err(|e| p!(e))?;

        let pub_key = message_attribute.get_u8_slice(AttributeKey::AttrPublicKey).map_err(|e| p!(e))?;

        Ok(Self { algorithm, challenge, pub_key: pub_key.to_vec() })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecBindingRequest {
    pub pub_key: Vec<u8>,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub tag: [u8; AES_GCM_TAG_SIZE],
    pub iv: [u8; AES_GCM_IV_SIZE],
    pub encrypt_data: Vec<u8>,
}

impl SecBindingRequest {
    pub fn encode(&self, _device_type: DeviceType) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrPublicKey, &self.pub_key);
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);
        attribute.set_u8_slice(AttributeKey::AttrTag, &self.tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &self.iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &self.encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());

        Ok(final_attribute.to_bytes()?)
    }

    pub fn decode(message: &[u8], _device_type: DeviceType) -> Result<Self, ErrorCode> {
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(AttributeKey::AttrMessage).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let pub_key_slice = message_attribute.get_u8_slice(AttributeKey::AttrPublicKey).map_err(|e| p!(e))?;
        let salt_slice = message_attribute.get_u8_slice(AttributeKey::AttrSalt).map_err(|e| p!(e))?;
        let tag_slice = message_attribute.get_u8_slice(AttributeKey::AttrTag).map_err(|e| p!(e))?;
        let iv_slice = message_attribute.get_u8_slice(AttributeKey::AttrIv).map_err(|e| p!(e))?;
        let encrypt_data_slice = message_attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        let salt: [u8; HKDF_SALT_SIZE] = salt_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;
        let tag: [u8; AES_GCM_TAG_SIZE] = tag_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;
        let iv: [u8; AES_GCM_IV_SIZE] = iv_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;

        Ok(Self { pub_key: pub_key_slice.to_vec(), salt, tag, iv, encrypt_data: encrypt_data_slice.to_vec() })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecBindingReply {
    pub tag: [u8; AES_GCM_TAG_SIZE],
    pub iv: [u8; AES_GCM_IV_SIZE],
    pub encrypt_data: Vec<u8>,
}

impl SecBindingReply {
    pub fn encode(&self, _device_type: DeviceType) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrTag, &self.tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &self.iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &self.encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());

        Ok(final_attribute.to_bytes()?)
    }

    pub fn decode(message: &[u8], _device_type: DeviceType) -> Result<Self, ErrorCode> {
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(AttributeKey::AttrMessage).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let tag_slice = message_attribute.get_u8_slice(AttributeKey::AttrTag).map_err(|e| p!(e))?;
        let iv_slice = message_attribute.get_u8_slice(AttributeKey::AttrIv).map_err(|e| p!(e))?;
        let encrypt_data_slice = message_attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        let tag: [u8; AES_GCM_TAG_SIZE] = tag_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;
        let iv: [u8; AES_GCM_IV_SIZE] = iv_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;

        Ok(Self { tag, iv, encrypt_data: encrypt_data_slice.to_vec() })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecBindingReplyInfo {
    pub device_id: String,
    pub user_id: i32,
    pub esl: i32,
    pub track_ability_level: i32,
    pub challenge: u64,
    pub protocal_list: Vec<u16>,
    pub capability_list: Vec<u16>,
}

impl SecBindingReplyInfo {
    pub fn encode(&self) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_string(AttributeKey::AttrDeviceId, self.device_id.clone());
        attribute.set_i32(AttributeKey::AttrUserId, self.user_id);

        attribute.set_i32(AttributeKey::AttrEsl, ExecutorSecurityLevel::Esl2 as i32);
        attribute.set_i32(AttributeKey::AttrTrackAbilityLevel, 0);
        attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);
        attribute.set_u16_slice(AttributeKey::AttrProtocolList, &self.protocal_list);
        attribute.set_u16_slice(AttributeKey::AttrCapabilityList, &self.capability_list);
        Ok(attribute.to_bytes()?)
    }

    pub fn decode(decrypt_data: &[u8]) -> Result<Self, ErrorCode> {
        let attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let device_id = attribute.get_string(AttributeKey::AttrDeviceId).map_err(|e| p!(e))?;
        let user_id = attribute.get_i32(AttributeKey::AttrUserId).map_err(|e| p!(e))?;
        let esl = attribute.get_i32(AttributeKey::AttrEsl).map_err(|e| p!(e))?;
        let track_ability_level = attribute.get_i32(AttributeKey::AttrTrackAbilityLevel).map_err(|e| p!(e))?;
        let challenge = attribute.get_u64(AttributeKey::AttrChallenge).map_err(|e| p!(e))?;
        let protocal_list = attribute.get_u16_vec(AttributeKey::AttrProtocolList).map_err(|e| p!(e))?;
        let capability_list = attribute.get_u16_vec(AttributeKey::AttrCapabilityList).map_err(|e| p!(e))?;

        Ok(Self { device_id, user_id, esl, track_ability_level, challenge, protocal_list, capability_list })
    }
}
