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

use crate::common::{constants::*, types::*};
use crate::entry::companion_device_auth_ffi::{
    DataArray1024Ffi, HostBeginAddCompanionInputFfi, HostBeginAddCompanionOutputFfi,
    HostEndAddCompanionInputFfi, HostEndAddCompanionOutputFfi, HostGetInitKeyNegotiationInputFfi,
    HostGetInitKeyNegotiationOutputFfi,
};
use crate::impls::default_host_db_manager::CURRENT_VERSION;
use crate::jobs::{host_db_helper, message_crypto};
use crate::traits::crypto_engine::KeyPair;
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngineRegistry};
use crate::traits::db_manager::{
    CompanionDeviceBaseInfo, CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk,
    DeviceKey, UserInfo,
};
use crate::traits::host_db_manager::{CompanionDeviceFilter, HostDbManagerRegistry};
use crate::traits::host_request_manager::{HostRequest, HostRequestInput, HostRequestOutput};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::String;
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyNegotialParam {
    pub device_type: DeviceType,
    pub algo_version: u16,
    pub challenge: u64,
    pub key_pair: Option<KeyPair>,
    pub sk: Vec<u8>, /* host pub_key or sk */
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCapability {
    pub device_type: DeviceType,
    pub esl: ExecutorSecurityLevel,
    pub track_ability_level: i32,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct EnrollParam {
    pub schedule_id: u64,
    pub host_device_key: DeviceKey,
    pub companion_device_key: DeviceKey,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct HostDeviceEnrollRequest {
    pub request_id: i32,
    pub secure_protocol_id: u16,
    pub enroll_param: EnrollParam,
    pub key_negotial_param: Vec<KeyNegotialParam>,
    pub device_capability: Vec<DeviceCapability>,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub acl: AuthCapabilityLevel,
}

impl HostDeviceEnrollRequest {
    pub fn new(input: &HostGetInitKeyNegotiationInputFfi) -> Result<Self, ErrorCode> {
        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get()
            .secure_random(&mut salt)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

        Ok(HostDeviceEnrollRequest {
            request_id: input.request_id,
            secure_protocol_id: input.secure_protocol_id,
            enroll_param: EnrollParam {
                schedule_id: 0,
                host_device_key: DeviceKey::default(),
                companion_device_key: DeviceKey::default(),
            },
            key_negotial_param: Vec::new(),
            device_capability: Vec::new(),
            salt: salt,
            acl: AuthCapabilityLevel::Acl0,
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn get_aes_gcm_param(&self, device_type: DeviceType) -> Result<KeyNegotialParam, ErrorCode> {
        for key_nego_param in &self.key_negotial_param {
            if device_type == key_nego_param.device_type {
                return Ok(key_nego_param.clone());
            }
        }
        return Err(ErrorCode::GeneralError);
    }

    fn create_prepare_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let algorithm_list = Vec::from([AlgoType::X25519 as u16]);
        let mut attribute = Attribute::new();
        attribute.set_u16_slice(AttributeKey::AttrAlgoList, &algorithm_list);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        Ok(final_attribute.to_bytes()?)
    }

    fn parse_begin_fwk_message(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let pub_key = MiscManagerRegistry::get_mut()
            .get_fwk_pub_key()
            .map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
        let attribute = message_codec
            .deserialize_attribute(fwk_message)
            .map_err(|e| p!(e))?;

        let schedule_id = attribute
            .get_u64(AttributeKey::AttrScheduleId)
            .map_err(|e| p!(e))?;

        if self.enroll_param.schedule_id != schedule_id {
            log_e!("scheduleId check fail");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn parse_key_nego_reply_data(
        &mut self,
        device_type: DeviceType,
        message_data: &[u8],
    ) -> Result<(), ErrorCode> {
        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let algo_version = message_attribute
            .get_u16(AttributeKey::AttrAlgoList)
            .map_err(|e| p!(e))?;
        let challenge = message_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;
        // The public key (pub_key) must be verified for legitimacy through the device certificate chain.
        let public_key = message_attribute
            .get_u8_slice(AttributeKey::AttrPublicKey)
            .map_err(|e| p!(e))?;

        let key_pair = CryptoEngineRegistry::get()
            .generate_x25519_key_pair()
            .map_err(|e| p!(e))?;
        let sk = CryptoEngineRegistry::get()
            .x25519_ecdh(&key_pair, public_key)
            .map_err(|e| {
                log_e!("x25519 computation failed for {:?}: {:?}", device_type, e);
                ErrorCode::GeneralError
            })?;
        let key_nego_param = KeyNegotialParam {
            device_type,
            algo_version,
            challenge,
            key_pair: Some(key_pair.clone()),
            sk,
        };
        self.key_negotial_param.push(key_nego_param);
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Err(e) = self.parse_key_nego_reply_data(DeviceType::None, value) {
                log_e!("parse common message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        if self.key_negotial_param.is_empty() {
            log_e!("no valid key negotiation parameters found");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut final_attribute = Attribute::new();
        for key_nego_param in &self.key_negotial_param {
            let mut attribute = Attribute::new();
            attribute.set_string(
                AttributeKey::AttrDeviceId,
                self.enroll_param.host_device_key.device_id.clone(),
            );
            attribute.set_i32(
                AttributeKey::AttrUserId,
                self.enroll_param.host_device_key.user_id,
            );
            let Some(key_pair) = key_nego_param.key_pair.as_ref() else {
                log_e!("x25519 key pair not set");
                return Err(ErrorCode::GeneralError);
            };
            attribute.set_u8_slice(AttributeKey::AttrPublicKey, &key_pair.pub_key);
            let session_key = CryptoEngineRegistry::get()
                .hkdf(&self.salt, &key_nego_param.sk)
                .map_err(|e| p!(e))?;

            let mut encrypt_attribute = Attribute::new();
            encrypt_attribute.set_string(
                AttributeKey::AttrDeviceId,
                self.enroll_param.host_device_key.device_id.clone(),
            );
            encrypt_attribute.set_i32(
                AttributeKey::AttrUserId,
                self.enroll_param.host_device_key.user_id,
            );
            encrypt_attribute.set_u64(AttributeKey::AttrChallenge, key_nego_param.challenge);
            let (encrypt_data, tag, iv) = message_crypto::encrypt_sec_message(
                encrypt_attribute.to_bytes()?.as_slice(),
                &session_key,
            )
            .map_err(|e| p!(e))?;
            attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);
            attribute.set_u8_slice(AttributeKey::AttrTag, &tag);
            attribute.set_u8_slice(AttributeKey::AttrIv, &iv);
            attribute.set_u8_slice(AttributeKey::AttrEncryptData, encrypt_data.as_slice());
            final_attribute
                .set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        }

        Ok(final_attribute.to_bytes()?)
    }

    fn parse_binding_reply_sec_message(
        &mut self,
        device_type: DeviceType,
        sec_message: &[u8],
    ) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        let device_id = attribute
            .get_string(AttributeKey::AttrDeviceId)
            .map_err(|e| p!(e))?;
        let user_id = attribute
            .get_i32(AttributeKey::AttrUserId)
            .map_err(|e| p!(e))?;
        let esl_value = attribute
            .get_i32(AttributeKey::AttrEsl)
            .map_err(|e| p!(e))?;
        let track_ability_level = attribute
            .get_i32(AttributeKey::AttrTrackAbilityLevel)
            .map_err(|e| p!(e))?;
        let tag = attribute
            .get_u8_slice(AttributeKey::AttrTag)
            .map_err(|e| p!(e))?;
        let iv = attribute
            .get_u8_slice(AttributeKey::AttrIv)
            .map_err(|e| p!(e))?;
        let encrypt_data = attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        let key_nego_param = self.get_aes_gcm_param(device_type).map_err(|e| p!(e))?;
        let session_key = CryptoEngineRegistry::get()
            .hkdf(&self.salt, &key_nego_param.sk)
            .map_err(|e| p!(e))?;
        let decrypt_data = message_crypto::decrypt_sec_message(encrypt_data, &session_key, tag, iv)
            .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let decrypt_device_id = decrypt_attribute
            .get_string(AttributeKey::AttrDeviceId)
            .map_err(|e| p!(e))?;
        let decrypt_user_id = decrypt_attribute
            .get_i32(AttributeKey::AttrUserId)
            .map_err(|e| p!(e))?;

        if device_id != decrypt_device_id {
            log_e!("device_id check fail, {}, {}", device_id, decrypt_device_id);
            return Err(ErrorCode::GeneralError);
        }

        if user_id != decrypt_user_id {
            log_e!("user_id check fail, {}, {}", user_id, decrypt_user_id);
            return Err(ErrorCode::GeneralError);
        }

        let esl = ExecutorSecurityLevel::try_from(esl_value).map_err(|e| p!(e))?;
        let device_capability = DeviceCapability {
            device_type,
            esl,
            track_ability_level,
        };

        self.device_capability.push(device_capability);
        let acl = match esl {
            ExecutorSecurityLevel::Esl0 => AuthCapabilityLevel::Acl0,
            ExecutorSecurityLevel::Esl1 => AuthCapabilityLevel::Acl2,
            ExecutorSecurityLevel::Esl2 => AuthCapabilityLevel::Acl3,
            ExecutorSecurityLevel::Esl3 | ExecutorSecurityLevel::MaxEsl => {
                log_e!("esl fail, esl: {:?}", esl);
                return Err(ErrorCode::GeneralError);
            }
        };
        if self.acl < acl {
            self.acl = acl;
        }
        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            self.parse_binding_reply_sec_message(DeviceType::None, value)?;
        }

        Ok(())
    }

    fn create_end_fwk_message(
        &mut self,
        result: i32,
        template_id: u64,
    ) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u64(AttributeKey::AttrScheduleId, self.enroll_param.schedule_id);
        attribute.set_i32(AttributeKey::AttrResultCode, result);
        attribute.set_u64(AttributeKey::AttrTemplateId, template_id);
        attribute.set_u64(AttributeKey::AttrPinSubType, 0);
        attribute.set_i32(AttributeKey::AttrRemainAttempts, 0);
        attribute.set_i32(AttributeKey::AttrLockoutDuration, 0);
        attribute.set_u32(AttributeKey::AttrCapabilityLevel, self.acl as u32);

        let local_key_pair = MiscManagerRegistry::get_mut()
            .get_local_key_pair()
            .map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Executor(local_key_pair));
        let fwk_messages = message_codec
            .serialize_attribute(&attribute)
            .map_err(|e| p!(e))?;
        Ok(fwk_messages)
    }

    fn init_device_info(
        &mut self,
    ) -> Result<
        (
            CompanionDeviceInfo,
            CompanionDeviceBaseInfo,
            Vec<CompanionDeviceCapability>,
            Vec<CompanionDeviceSk>,
        ),
        ErrorCode,
    > {
        let template_id = HostDbManagerRegistry::get()
            .generate_unique_template_id()
            .map_err(|e| p!(e))?;
        let device_info = CompanionDeviceInfo {
            template_id,
            device_key: self.enroll_param.companion_device_key.clone(),
            user_info: UserInfo {
                user_id: self.enroll_param.host_device_key.user_id,
                user_type: 0,
            },
            added_time: TimeKeeperRegistry::get()
                .get_rtc_time()
                .map_err(|e| p!(e))?,
            secure_protocol_id: self.secure_protocol_id,
            is_valid: true,
        };

        let base_info = CompanionDeviceBaseInfo {
            device_model: String::new(),
            device_name: String::new(),
            device_user_name: String::new(),
            business_ids: Vec::new(),
        };

        let mut capability_infos: Vec<CompanionDeviceCapability> = Vec::new();
        let mut sk_infos: Vec<CompanionDeviceSk> = Vec::new();
        for device_capability in &self.device_capability {
            let capability_info = CompanionDeviceCapability {
                device_type: device_capability.device_type,
                esl: device_capability.esl,
                track_ability_level: device_capability.track_ability_level,
            };
            capability_infos.push(capability_info);
        }

        for key_nego_param in &self.key_negotial_param {
            let sk_info = CompanionDeviceSk {
                device_type: key_nego_param.device_type,
                sk: key_nego_param.sk.clone(),
            };
            sk_infos.push(sk_info);
        }

        Ok((device_info, base_info, capability_infos, sk_infos))
    }

    fn store_device_info(&mut self) -> Result<u64, ErrorCode> {
        let (device_info, device_base_info, capability_infos, sk_infos) =
            self.init_device_info()?;
        host_db_helper::add_companion_device(
            &device_info,
            &device_base_info,
            capability_infos,
            sk_infos,
        )?;
        Ok(device_info.template_id)
    }
}

impl HostRequest for HostDeviceEnrollRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_e!("HostDeviceEnrollRequest prepare not implemented");
        let HostRequestInput::KeyNego(_ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        let sec_message = self.create_prepare_sec_message()?;

        Ok(HostRequestOutput::KeyNego(
            HostGetInitKeyNegotiationOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn begin(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDeviceEnrollRequest begin start");
        let HostRequestInput::EnrollBegin(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        let host_device_key = DeviceKey::try_from(&ffi_input.host_device_key)?;
        let companion_device_key = DeviceKey::try_from(&ffi_input.companion_device_key)?;
        self.enroll_param.host_device_key = host_device_key;
        self.enroll_param.companion_device_key = companion_device_key;
        self.enroll_param.schedule_id = ffi_input.schedule_id;

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice())?;
        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;

        let sec_message = self.create_begin_sec_message()?;
        Ok(HostRequestOutput::EnrollBegin(
            HostBeginAddCompanionOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn end(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDeviceEnrollRequest end start");
        let HostRequestInput::EnrollEnd(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice())?;
        let template_id = self.store_device_info()?;

        let fwk_message = self.create_end_fwk_message(0, template_id)?;
        Ok(HostRequestOutput::EnrollEnd(HostEndAddCompanionOutputFfi {
            fwk_message: DataArray1024Ffi::try_from(fwk_message).map_err(|e| p!(e))?,
            template_id: template_id,
        }))
    }
}
