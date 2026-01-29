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
use crate::entry::companion_device_auth_ffi::HostGetInitKeyNegotiationInputFfi;
use crate::jobs::{host_db_helper, message_crypto};
use crate::request::enroll::enroll_message::{
    FwkEnrollReply, FwkEnrollRequest, SecBindingReply, SecBindingReplyInfo, SecBindingRequest, SecKeyNegoReply,
    SecKeyNegoRequest,
};
use crate::request::jobs::common_message::SecIssueToken;
use crate::request::jobs::token_helper;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair};
use crate::traits::db_manager::{
    CompanionDeviceBaseInfo, CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk, CompanionTokenInfo,
    DeviceKey, UserInfo,
};
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::{Attribute, AttributeKey};
use crate::String;
use crate::{log_e, log_i, p, Box, Vec};
use token_helper::DeviceTokenInfo;

#[derive(Debug, Clone, PartialEq)]
pub struct KeyNegotialParam {
    pub device_type: DeviceType,
    pub algorithm: u16,
    pub challenge: u64,
    pub key_pair: Option<KeyPair>,
    pub sk: Vec<u8>, /* host pub_key or sk */
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCapability {
    pub device_type: DeviceType,
    pub esl: ExecutorSecurityLevel,
    pub track_ability_level: TrackAbilityLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnrollParam {
    pub schedule_id: u64,
    pub host_device_key: DeviceKey,
    pub companion_device_key: DeviceKey,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostDeviceEnrollRequest {
    pub request_id: i32,
    pub secure_protocol_id: u16,
    pub enroll_param: EnrollParam,
    pub key_negotial_param: Vec<KeyNegotialParam>,
    pub device_capability: Vec<DeviceCapability>,
    pub token_infos: Vec<DeviceTokenInfo>,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub acl: AuthCapabilityLevel,
    pub atl: AuthTrustLevel,
}

impl HostDeviceEnrollRequest {
    pub fn new(input: &HostGetInitKeyNegotiationInputFfi) -> Result<Self, ErrorCode> {
        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
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
            token_infos: Vec::new(),
            salt,
            acl: AuthCapabilityLevel::Acl0,
            atl: AuthTrustLevel::Atl0,
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
        log_e!("get_aes_gcm_param fail");
        Err(ErrorCode::GeneralError)
    }

    fn create_prepare_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let key_nego_request = Box::new(SecKeyNegoRequest { algorithm_list: Vec::from([AlgoType::X25519 as u16]) });
        let output = match SecureProtocolId::try_from(self.secure_protocol_id).map_err(|e| p!(e))? {
            SecureProtocolId::Default => key_nego_request.encode(DeviceType::Default)?,
            _ => {
                log_e!("secure_protocol_id type is not support, secure_protocol_id: {}", self.secure_protocol_id);
                return Err(ErrorCode::GeneralError);
            },
        };
        Ok(output)
    }

    fn parse_begin_fwk_message(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let output = FwkEnrollRequest::decode(fwk_message)?;
        if self.enroll_param.schedule_id != output.schedule_id {
            log_e!("scheduleId check fail");
            return Err(ErrorCode::GeneralError);
        }

        self.atl = AuthTrustLevel::try_from(output.atl).map_err(|_| {
            log_e!("Invalid ATL value: {}", output.atl);
            ErrorCode::GeneralError
        })?;
        Ok(())
    }

    fn parse_key_nego_reply(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecKeyNegoReply::decode(sec_message, device_type)?;
        let key_pair = CryptoEngineRegistry::get().generate_x25519_key_pair().map_err(|e| p!(e))?;
        let sk = CryptoEngineRegistry::get()
            .x25519_ecdh(&key_pair, &output.pub_key)
            .map_err(|e| {
                log_e!("x25519 computation failed for {:?}: {:?}", device_type, e);
                ErrorCode::GeneralError
            })?;
        let key_nego_param = KeyNegotialParam {
            device_type,
            algorithm: output.algorithm,
            challenge: output.challenge,
            key_pair: Some(key_pair.clone()),
            sk,
        };
        self.key_negotial_param.push(key_nego_param);
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        match SecureProtocolId::try_from(self.secure_protocol_id).map_err(|e| p!(e))? {
            SecureProtocolId::Default => {
                if let Err(e) = self.parse_key_nego_reply(DeviceType::Default, sec_message) {
                    log_e!("parse key nego reply message fail: {:?}", e);
                    return Err(ErrorCode::GeneralError);
                }
            },
            _ => {
                log_e!("secure_protocol_id type is not support, secure_protocol_id: {}", self.secure_protocol_id);
                return Err(ErrorCode::GeneralError);
            },
        }

        if self.key_negotial_param.is_empty() {
            log_e!("no valid key negotiation parameters found");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        for key_nego_param in &self.key_negotial_param {
            let Some(key_pair) = key_nego_param.key_pair.as_ref() else {
                log_e!("x25519 key pair not set");
                return Err(ErrorCode::GeneralError);
            };
            let session_key = CryptoEngineRegistry::get()
                .hkdf(&self.salt, &key_nego_param.sk)
                .map_err(|e| p!(e))?;

            let mut encrypt_attribute = Attribute::new();
            encrypt_attribute
                .set_string(AttributeKey::AttrDeviceId, self.enroll_param.host_device_key.device_id.clone());
            encrypt_attribute.set_i32(AttributeKey::AttrUserId, self.enroll_param.host_device_key.user_id);
            encrypt_attribute.set_u64(AttributeKey::AttrChallenge, key_nego_param.challenge);
            let (encrypt_data, tag, iv) =
                message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), &session_key)
                    .map_err(|e| p!(e))?;

            let binding_request = Box::new(SecBindingRequest {
                pub_key: key_pair.pub_key.clone(),
                salt: self.salt,
                tag,
                iv,
                encrypt_data,
            });

            output.extend(binding_request.encode(key_nego_param.device_type)?);
        }

        Ok(output)
    }

    fn parse_binding_reply(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecBindingReply::decode(sec_message, device_type)?;

        let key_nego_param = self.get_aes_gcm_param(device_type).map_err(|e| p!(e))?;
        let session_key = CryptoEngineRegistry::get()
            .hkdf(&self.salt, &key_nego_param.sk)
            .map_err(|e| p!(e))?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let reply_info = SecBindingReplyInfo::decode(&decrypt_data)?;

        if self.enroll_param.companion_device_key.device_id != reply_info.device_id {
            log_e!(
                "device_id check fail, {}, {}",
                self.enroll_param.companion_device_key.device_id,
                reply_info.device_id
            );
            return Err(ErrorCode::GeneralError);
        }

        if self.enroll_param.companion_device_key.user_id != reply_info.user_id {
            log_e!("user_id check fail, {}, {}", self.enroll_param.companion_device_key.user_id, reply_info.user_id);
            return Err(ErrorCode::GeneralError);
        }
        if reply_info.protocol_list != PROTOCOL_VERSION {
            log_e!("protocol version is error, {:?}", reply_info.protocol_list);
            return Err(ErrorCode::GeneralError);
        }

        if reply_info.capability_list != SUPPORT_CAPABILITY {
            log_e!("capability_list is error, {:?}", reply_info.capability_list);
            return Err(ErrorCode::GeneralError);
        }

        let esl = ExecutorSecurityLevel::try_from(reply_info.esl).map_err(|e| p!(e))?;
        let device_capability = DeviceCapability {
            device_type,
            esl,
            track_ability_level: TrackAbilityLevel::try_from(reply_info.track_ability_level).map_err(|e| p!(e))?,
        };
        self.device_capability.push(device_capability);
        self.token_infos
            .push(token_helper::generate_token(device_type, reply_info.challenge, self.atl)?);

        let acl = match esl {
            ExecutorSecurityLevel::Esl0 => AuthCapabilityLevel::Acl0,
            ExecutorSecurityLevel::Esl1 => AuthCapabilityLevel::Acl1,
            ExecutorSecurityLevel::Esl2 => AuthCapabilityLevel::Acl2,
            ExecutorSecurityLevel::Esl3 => AuthCapabilityLevel::Acl3,
        };
        if self.acl < acl {
            self.acl = acl;
        }
        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let device_types: Vec<DeviceType> = self.key_negotial_param.iter().map(|param| param.device_type).collect();
        for device_type in device_types {
            if let Err(e) = self.parse_binding_reply(device_type, sec_message) {
                log_e!("parse binding reply message fail: device_type: {:?}, result: {:?}", device_type, e);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn create_end_sec_message(&mut self, template_id: u64) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        for token_info in &self.token_infos {
            let session_key = host_db_helper::get_session_key(template_id, token_info.device_type, &self.salt)?;
            let issue_token = SecIssueToken {
                challenge: token_info.challenge,
                atl: self.atl as i32,
                token: token_info.token.clone(),
            };
            output.extend(issue_token.encrypt_issue_token(&self.salt, token_info.device_type, &session_key)?);
        }
        Ok(output)
    }

    fn create_end_fwk_message(&mut self, result: i32, template_id: u64) -> Result<Vec<u8>, ErrorCode> {
        let fwk_enroll_reply = Box::new(FwkEnrollReply {
            schedule_id: self.enroll_param.schedule_id,
            template_id,
            result_code: result,
            acl: self.acl as u32,
            pin_sub_type: 0,
            remain_attempts: 0,
            lock_duration: 0,
        });
        let output = fwk_enroll_reply.encode()?;
        Ok(output)
    }

    fn init_device_info(
        &mut self,
    ) -> Result<
        (
            Box<CompanionDeviceInfo>,
            Box<CompanionDeviceBaseInfo>,
            Vec<CompanionDeviceCapability>,
            Vec<CompanionDeviceSk>,
        ),
        ErrorCode,
    > {
        let template_id = HostDbManagerRegistry::get().generate_unique_template_id().map_err(|e| p!(e))?;
        let device_info = Box::new(CompanionDeviceInfo {
            template_id,
            device_key: self.enroll_param.companion_device_key.clone(),
            user_info: UserInfo { user_id: self.enroll_param.host_device_key.user_id, user_type: 0 },
            added_time: TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?,
            secure_protocol_id: self.secure_protocol_id,
            is_valid: true,
        });

        let base_info = Box::new(CompanionDeviceBaseInfo {
            device_model: String::new(),
            device_name: String::new(),
            device_user_name: String::new(),
            business_ids: Vec::new(),
        });

        let mut capability_infos: Vec<CompanionDeviceCapability> = Vec::new();
        for device_capability in &self.device_capability {
            let capability_info = CompanionDeviceCapability {
                device_type: device_capability.device_type,
                esl: device_capability.esl,
                track_ability_level: device_capability.track_ability_level,
            };
            capability_infos.push(capability_info);
        }

        let mut sk_infos: Vec<CompanionDeviceSk> = Vec::new();
        for key_nego_param in &self.key_negotial_param {
            let sk_info = CompanionDeviceSk {
                device_type: key_nego_param.device_type,
                sk: key_nego_param.sk.clone().try_into().map_err(|_| ErrorCode::GeneralError)?,
            };
            sk_infos.push(sk_info);
        }

        Ok((device_info, base_info, capability_infos, sk_infos))
    }

    fn store_device_info(&mut self) -> Result<CompanionDeviceInfo, ErrorCode> {
        let (device_info, device_base_info, capability_infos, sk_infos) = self.init_device_info()?;
        HostDbManagerRegistry::get_mut().add_device(&device_info, &device_base_info, &capability_infos, &sk_infos)?;
        Ok(*device_info)
    }

    fn store_token(&self, template_id: u64) -> Result<(), ErrorCode> {
        for token_info in &self.token_infos {
            let companion_token = CompanionTokenInfo {
                template_id,
                device_type: token_info.device_type,
                token: token_info.token.clone().try_into().map_err(|_| ErrorCode::GeneralError)?,
                atl: self.atl,
                added_time: TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?,
            };
            HostDbManagerRegistry::get_mut().add_token(&companion_token)?;
        }

        Ok(())
    }
}

impl Request for HostDeviceEnrollRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceEnrollRequest prepare start");
        let RequestParam::HostKeyNego(_ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        let sec_message = self.create_prepare_sec_message()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceEnrollRequest begin start");
        let RequestParam::HostEnrollBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        let host_device_key = DeviceKey::try_from(&ffi_input.host_device_key)?;
        let companion_device_key = DeviceKey::try_from(&ffi_input.companion_device_key)?;
        self.enroll_param.host_device_key = host_device_key;
        self.enroll_param.companion_device_key = companion_device_key;
        self.enroll_param.schedule_id = ffi_input.schedule_id;

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice()?)?;
        self.parse_begin_sec_message(ffi_input.sec_message.as_slice()?)?;

        let sec_message = self.create_begin_sec_message()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceEnrollRequest end start");
        let RequestParam::HostEnrollEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice()?)?;
        let device_info = self.store_device_info()?;
        self.store_token(device_info.template_id)?;

        let fwk_message = self.create_end_fwk_message(0, device_info.template_id)?;
        let sec_message = self.create_end_sec_message(device_info.template_id)?;
        ffi_output.fwk_message.copy_from_vec(&fwk_message)?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        ffi_output.template_id = device_info.template_id;
        ffi_output.atl = self.atl as i32;
        ffi_output.added_time = device_info.added_time;
        Ok(())
    }
}
