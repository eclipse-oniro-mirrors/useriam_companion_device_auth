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

use crate::common::constants::{
    AlgoType, AuthCapabilityLevel, AuthTrustLevel, ErrorCode, ExecutorSecurityLevel, ProcessorType, SecureProtocolId,
    TrackAbilityLevel, CHALLENGE_LEN, HKDF_SALT_SIZE, TOKEN_VALID_PERIOD,
};
use crate::entry::companion_device_auth_ffi::HostGetInitKeyNegotiationInputFfi;
use crate::jobs::{companion_device_db_helper, message_crypto};
use crate::request::enroll::enroll_message::{
    FwkEnrollReply, FwkEnrollRequest, SecBindingReply, SecBindingReplyInfo, SecBindingRequest, SecKeyNegoReply,
    SecKeyNegoRequest,
};
use crate::request::jobs::common_message::SecIssueToken;
use crate::request::jobs::token_helper;
use crate::traits::companion_device_db_manager::CompanionDeviceDbManagerRegistry;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair};
use crate::traits::db_manager::{
    CompanionDevice, CompanionDeviceCapability, CompanionDeviceProfile, CompanionDeviceSk, CompanionDeviceToken,
    DeviceKey, UserInfo,
};
use crate::traits::log_trace::RustFileId;
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::{Attribute, AttributeKey};
use crate::String;
use crate::{log_e, log_i, p, Box, Vec};
use token_helper::DeviceTokenInfo;
pub(crate) const FILE_ID: u16 = RustFileId::HostEnroll as u16;
#[derive(Debug, Clone, PartialEq)]
pub struct KeyNegotialParam {
    pub processor_type: ProcessorType,
    pub algorithm: u16,
    pub companion_challenge: u64,
    pub key_pair: Option<KeyPair>,
    pub sk: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCapability {
    pub processor_type: ProcessorType,
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
    pub host_challenge: u64,
    pub acl: AuthCapabilityLevel,
    pub atl: AuthTrustLevel,
    pub expected_protocol_list: Vec<u16>,
    pub expected_capability_list: Vec<u16>,
    pub device_model_info: String,
    pub device_name: String,
    pub device_user_name: String,
    pub device_type: i32,
    pub algorithm_list: Vec<u16>,
    pub selected_algorithm: u16,
}

impl HostDeviceEnrollRequest {
    pub fn new(input: &HostGetInitKeyNegotiationInputFfi) -> Result<Self, ErrorCode> {
        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
            log_e!("secure_random salt fail");
            ErrorCode::GeneralError
        })?;

        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random challenge fail");
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
            host_challenge: u64::from_ne_bytes(challenge),
            salt,
            acl: AuthCapabilityLevel::Acl0,
            atl: AuthTrustLevel::Atl0,
            expected_protocol_list: Vec::new(),
            expected_capability_list: Vec::new(),
            device_model_info: String::new(),
            device_name: String::new(),
            device_user_name: String::new(),
            device_type: 0,
            algorithm_list: Vec::new(),
            selected_algorithm: 0,
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn get_aes_gcm_param(&self, processor_type: ProcessorType) -> Result<KeyNegotialParam, ErrorCode> {
        for key_nego_param in &self.key_negotial_param {
            if processor_type == key_nego_param.processor_type {
                return Ok(key_nego_param.clone());
            }
        }
        log_e!("get_aes_gcm_param fail");
        Err(ErrorCode::GeneralError)
    }

    fn update_aes_gcm_param(
        &mut self,
        processor_type: ProcessorType,
        key_nego_param: &KeyNegotialParam,
    ) -> Result<(), ErrorCode> {
        let index = self
            .key_negotial_param
            .iter()
            .position(|key_nego_param| processor_type == key_nego_param.processor_type)
            .ok_or_else(|| {
                log_e!("no processor_type matching");
                ErrorCode::NotFound
            })?;
        self.key_negotial_param[index] = key_nego_param.clone();
        Ok(())
    }

    fn encode_sec_algo_nego_request(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let algorithm_list = Vec::from([AlgoType::X25519 as u16]);
        let key_nego_request = Box::new(SecKeyNegoRequest { algorithm_list: algorithm_list.clone() });
        let output = match SecureProtocolId::try_from(self.secure_protocol_id).map_err(|e| p!(e))? {
            SecureProtocolId::Default => key_nego_request.encode(ProcessorType::default())?,
            _ => {
                log_e!("secure_protocol_id is not supported: {}", self.secure_protocol_id);
                return Err(ErrorCode::GeneralError);
            },
        };
        self.algorithm_list = algorithm_list;
        Ok(output)
    }

    fn decode_fwk_binding_request(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
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

    fn decode_sec_key_nego_reply_message(
        &mut self,
        processor_type: ProcessorType,
        sec_message: &[u8],
    ) -> Result<(), ErrorCode> {
        let output = SecKeyNegoReply::decode(sec_message, processor_type)?;
        let key_pair = CryptoEngineRegistry::get().generate_x25519_key_pair().map_err(|e| p!(e))?;
        let sk = CryptoEngineRegistry::get().x25519_ecdh(&key_pair, &output.pub_key).map_err(|e| {
            log_e!("x25519 computation failed for {:?}: {:?}", processor_type, e);
            ErrorCode::GeneralError
        })?;
        let key_nego_param = KeyNegotialParam {
            processor_type,
            algorithm: output.algorithm,
            companion_challenge: output.challenge,
            key_pair: Some(key_pair.clone()),
            sk,
        };
        self.key_negotial_param.push(key_nego_param);
        self.selected_algorithm = output.algorithm;
        Ok(())
    }

    fn decode_sec_key_nego_reply(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        match SecureProtocolId::try_from(self.secure_protocol_id).map_err(|e| p!(e))? {
            SecureProtocolId::Default => {
                if let Err(e) = self.decode_sec_key_nego_reply_message(ProcessorType::default(), sec_message) {
                    log_e!("parse key nego reply message fail: {:?}", e);
                    return Err(ErrorCode::GeneralError);
                }
            },
            _ => {
                log_e!("secure_protocol_id is not supported: {}", self.secure_protocol_id);
                return Err(ErrorCode::GeneralError);
            },
        }

        if self.key_negotial_param.is_empty() {
            log_e!("no valid key negotiation parameters found");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn encode_sec_binding_request(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        for key_nego_param in &self.key_negotial_param {
            let Some(key_pair) = key_nego_param.key_pair.as_ref() else {
                log_e!("x25519 key pair not set");
                return Err(ErrorCode::GeneralError);
            };
            let session_key = CryptoEngineRegistry::get().hkdf(&self.salt, &key_nego_param.sk).map_err(|e| p!(e))?;

            let mut encrypt_attribute = Attribute::new();
            encrypt_attribute
                .set_string(AttributeKey::AttrDeviceId, self.enroll_param.host_device_key.device_id.clone());
            encrypt_attribute.set_i32(AttributeKey::AttrUserId, self.enroll_param.host_device_key.user_id);
            encrypt_attribute.set_u64(AttributeKey::AttrCompanionChallenge, key_nego_param.companion_challenge);
            let (encrypt_data, tag, iv) =
                message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), &session_key)
                    .map_err(|e| p!(e))?;

            let binding_request = Box::new(SecBindingRequest {
                pub_key: key_pair.pub_key.clone(),
                challenge: self.host_challenge,
                salt: self.salt,
                tag,
                iv,
                encrypt_data,
            });

            output.extend(binding_request.encode(key_nego_param.processor_type)?);
        }

        Ok(output)
    }

    fn decode_sec_binding_reply_message(
        &mut self,
        processor_type: ProcessorType,
        sec_message: &[u8],
    ) -> Result<(), ErrorCode> {
        let output = SecBindingReply::decode(sec_message, processor_type)?;

        let mut key_nego_param = self.get_aes_gcm_param(processor_type).map_err(|e| p!(e))?;
        let session_key = CryptoEngineRegistry::get().hkdf(&self.salt, &key_nego_param.sk).map_err(|e| p!(e))?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let reply_info = SecBindingReplyInfo::decode(&decrypt_data)?;

        if self.host_challenge != reply_info.challenge {
            log_e!("challenge check fail");
            return Err(ErrorCode::GeneralError);
        }

        if self.enroll_param.companion_device_key.device_id != reply_info.device_id {
            log_e!("device_id check fail");
            return Err(ErrorCode::GeneralError);
        }

        if self.enroll_param.companion_device_key.user_id != reply_info.user_id {
            log_e!(
                "user_id check fail, expected: {}, got: {}",
                self.enroll_param.companion_device_key.user_id,
                reply_info.user_id
            );
            return Err(ErrorCode::GeneralError);
        }

        if reply_info.protocol_list != self.expected_protocol_list {
            log_e!(
                "protocol verification failed, expected: {:?}, actual: {:?}",
                self.expected_protocol_list,
                reply_info.protocol_list
            );
            return Err(ErrorCode::GeneralError);
        }

        if reply_info.capability_list != self.expected_capability_list {
            log_e!(
                "capability verification failed, expected: {:?}, actual: {:?}",
                self.expected_capability_list,
                reply_info.capability_list
            );
            return Err(ErrorCode::GeneralError);
        }

        key_nego_param.companion_challenge = output.challenge;
        self.update_aes_gcm_param(processor_type, &key_nego_param)?;

        let esl = ExecutorSecurityLevel::try_from(reply_info.esl).map_err(|e| p!(e))?;
        let device_capability = DeviceCapability {
            processor_type,
            esl,
            track_ability_level: TrackAbilityLevel::try_from(reply_info.track_ability_level).map_err(|e| p!(e))?,
        };
        self.device_capability.push(device_capability);
        self.token_infos.push(token_helper::generate_token(
            processor_type,
            key_nego_param.companion_challenge,
            self.atl,
        )?);

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

    fn decode_sec_binding_reply(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let processor_types: Vec<ProcessorType> =
            self.key_negotial_param.iter().map(|param| param.processor_type).collect();
        for processor_type in processor_types {
            if let Err(e) = self.decode_sec_binding_reply_message(processor_type, sec_message) {
                log_e!("parse binding reply message fail: processor_type: {:?}, result: {:?}", processor_type, e);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn encode_sec_token_issue(&mut self, template_id: u64) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        for token_info in &self.token_infos {
            let session_key =
                companion_device_db_helper::get_session_key(template_id, token_info.processor_type, &self.salt)?;
            let issue_token = SecIssueToken {
                challenge: token_info.challenge,
                atl: self.atl as i32,
                token: token_info.token.clone(),
            };
            output.extend(issue_token.encrypt_issue_token(&self.salt, token_info.processor_type, &session_key)?);
        }
        Ok(output)
    }

    fn encode_fwk_binding_reply(&mut self, result: i32, template_id: u64) -> Result<Vec<u8>, ErrorCode> {
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
        (Box<CompanionDevice>, Box<CompanionDeviceProfile>, Vec<CompanionDeviceCapability>, Vec<CompanionDeviceSk>),
        ErrorCode,
    > {
        let template_id = CompanionDeviceDbManagerRegistry::get().generate_unique_template_id().map_err(|e| p!(e))?;
        let device_info = Box::new(CompanionDevice {
            template_id,
            device_key: self.enroll_param.companion_device_key.clone(),
            user_info: UserInfo { user_id: self.enroll_param.host_device_key.user_id, user_type: 0 },
            added_time: TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?,
            is_valid: true,
            capability_list: self.expected_capability_list.clone(),
        });

        let base_info = Box::new(CompanionDeviceProfile {
            device_model_info: self.device_model_info.clone(),
            device_name: self.device_name.clone(),
            device_user_name: self.device_user_name.clone(),
            business_ids: Vec::new(),
            device_type: self.device_type,
        });

        let mut capability_infos: Vec<CompanionDeviceCapability> = Vec::new();
        for device_capability in &self.device_capability {
            let capability_info = CompanionDeviceCapability {
                processor_type: device_capability.processor_type,
                esl: device_capability.esl,
                track_ability_level: device_capability.track_ability_level,
            };
            capability_infos.push(capability_info);
        }

        let mut sk_infos: Vec<CompanionDeviceSk> = Vec::new();
        for key_nego_param in &self.key_negotial_param {
            let sk_info = CompanionDeviceSk {
                processor_type: key_nego_param.processor_type,
                sk: key_nego_param.sk.clone().try_into().map_err(|e| {
                    log_e!("try_into fail: {:?}", e);
                    ErrorCode::GeneralError
                })?,
            };
            sk_infos.push(sk_info);
        }

        Ok((device_info, base_info, capability_infos, sk_infos))
    }

    fn store_device_info(&mut self) -> Result<CompanionDevice, ErrorCode> {
        let (device_info, device_profile, capability_infos, sk_infos) = self.init_device_info()?;
        CompanionDeviceDbManagerRegistry::get_mut().add_device(
            &device_info,
            &device_profile,
            &capability_infos,
            &sk_infos,
        )?;
        Ok(*device_info)
    }

    fn store_token(&self, template_id: u64) -> Result<(), ErrorCode> {
        for token_info in &self.token_infos {
            let issue_time = TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?;
            let companion_token = CompanionDeviceToken {
                template_id,
                processor_type: token_info.processor_type,
                token: token_info.token.clone().try_into().map_err(|e| {
                    log_e!("try_into fail: {:?}", e);
                    ErrorCode::GeneralError
                })?,
                atl: self.atl,
                expire_time: issue_time.checked_add(TOKEN_VALID_PERIOD).ok_or_else(|| {
                    log_e!("expire_time overflow");
                    ErrorCode::GeneralError
                })?,
                issue_time,
            };
            CompanionDeviceDbManagerRegistry::get_mut().add_token(&companion_token)?;
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

        let sec_message = self.encode_sec_algo_nego_request()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;

        let (algo_data, algo_len) = crate::commands::common_command::try_array_from_vec(self.algorithm_list.clone())?;
        ffi_output.algorithm_list.data = algo_data;
        ffi_output.algorithm_list.len = algo_len;
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

        self.decode_fwk_binding_request(ffi_input.fwk_message.as_slice()?)?;
        self.decode_sec_key_nego_reply(ffi_input.sec_message.as_slice()?)?;

        let sec_message = self.encode_sec_binding_request()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        ffi_output.selected_algorithm = self.selected_algorithm;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceEnrollRequest end start");
        let RequestParam::HostEnrollEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.expected_protocol_list = Vec::<u16>::try_from(ffi_input.protocol_list).map_err(|e| {
            log_e!("Failed to convert protocol_list: {:?}", e);
            ErrorCode::GeneralError
        })?;

        self.expected_capability_list = Vec::<u16>::try_from(ffi_input.capability_list).map_err(|e| {
            log_e!("Failed to convert capability_list: {:?}", e);
            ErrorCode::GeneralError
        })?;

        self.device_model_info = ffi_input.companion_status.device_model_info.to_string().unwrap_or_default();
        self.device_name = ffi_input.companion_status.device_name.to_string().unwrap_or_default();
        self.device_user_name = ffi_input.companion_status.device_user_name.to_string().unwrap_or_default();
        self.device_type = ffi_input.companion_status.device_type;

        self.decode_sec_binding_reply(ffi_input.sec_message.as_slice()?)?;
        let device_info = self.store_device_info()?;
        self.store_token(device_info.template_id)?;

        let fwk_message = self.encode_fwk_binding_reply(0, device_info.template_id)?;
        let sec_message = self.encode_sec_token_issue(device_info.template_id)?;
        ffi_output.fwk_message.copy_from_vec(&fwk_message)?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        ffi_output.template_id = device_info.template_id;
        // Calculate the max ATL from token_infos
        let max_atl = self.token_infos.iter().map(|info| info.atl as i32).max().unwrap_or(self.atl as i32);
        ffi_output.atl = max_atl;
        let esl = self.device_capability.iter().map(|cap| cap.esl).max().unwrap_or(ExecutorSecurityLevel::Esl0);
        ffi_output.esl = esl as i32;
        ffi_output.added_time = device_info.added_time;
        Ok(())
    }
}
