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
    AlgoType, AuthTrustLevel, ErrorCode, ExecutorSecurityLevel, ProcessorType, TrackAbilityLevel, CHALLENGE_LEN,
    HKDF_SALT_SIZE, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::entry::companion_device_auth_ffi::{
    CompanionInitKeyNegotiationInputFfi, DeviceKeyFfi, PersistedHostBindingStatusFfi,
};
use crate::jobs::host_binding_db_helper;
use crate::jobs::message_crypto;
use crate::request::enroll::enroll_message::{
    SecBindingReply, SecBindingReplyInfo, SecBindingRequest, SecKeyNegoReply, SecKeyNegoRequest,
};
use crate::request::jobs::common_message::SecIssueToken;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair};
use crate::traits::db_manager::{DeviceKey, HostBinding, HostBindingSk, HostBindingToken, UserInfo};
use crate::traits::host_binding_db_manager::HostBindingDbManagerRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};
use crate::traits::log_trace::RustFileId;
pub(crate) const FILE_ID: u16 = RustFileId::CompanionEnroll as u16;

#[derive(Debug, Clone, PartialEq)]
pub struct KeyNegoParam {
    pub request_id: i32,
    pub companion_device_key: DeviceKey,
    pub host_device_key: DeviceKey,
    pub companion_challenge: u64,
    pub key_pair: Option<KeyPair>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BindingParam {
    pub public_key: Vec<u8>,
    pub host_challenge: u64,
    pub salt: [u8; HKDF_SALT_SIZE],
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenInfo {
    pub token: Vec<u8>,
    pub atl: AuthTrustLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionDeviceEnrollRequest {
    pub secure_protocol_id: u16,
    pub protocol_list: Vec<u16>,
    pub capability_list: Vec<u16>,
    pub key_nego_param: KeyNegoParam,
    pub binding_param: BindingParam,
    pub session_key: Vec<u8>,
    pub sk: Vec<u8>,
    pub binding_id: i32,
    pub token_info: TokenInfo,
    pub algorithm_list: Vec<u16>,
    pub selected_algorithm: u16,
}

impl CompanionDeviceEnrollRequest {
    pub fn new(input: &CompanionInitKeyNegotiationInputFfi) -> Result<Self, ErrorCode> {
        let host_device_key = DeviceKey::try_from(&input.host_device_key)?;
        let companion_device_key = DeviceKey::try_from(&input.companion_device_key)?;

        let protocol_list: Vec<u16> = input.protocol_list.try_into().map_err(|e| {
            log_e!("protocol_list try_into fail: {:?}", e);
            ErrorCode::GeneralError
        })?;
        let capability_list = input.capability_list.try_into().map_err(|e| {
            log_e!("capability_list try_into fail: {:?}", e);
            ErrorCode::GeneralError
        })?;

        // Validate that SA's protocol_list is a subset of TA's SUPPORTED_PROTOCOL_VERSIONS
        for protocol in &protocol_list {
            if !SUPPORTED_PROTOCOL_VERSIONS.contains(protocol) {
                log_e!("protocol {} is not supported by TA, supported: {:?}", protocol, SUPPORTED_PROTOCOL_VERSIONS);
                return Err(ErrorCode::GeneralError);
            }
        }

        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random challenge fail");
            ErrorCode::GeneralError
        })?;
        Ok(Self {
            secure_protocol_id: input.secure_protocol_id,
            protocol_list,
            capability_list,
            key_nego_param: KeyNegoParam {
                request_id: input.request_id,
                companion_device_key,
                host_device_key,
                companion_challenge: u64::from_ne_bytes(challenge),
                key_pair: None,
            },
            binding_param: BindingParam { public_key: Vec::new(), host_challenge: 0, salt: [0u8; HKDF_SALT_SIZE] },
            session_key: Vec::new(),
            sk: Vec::new(),
            binding_id: 0,
            token_info: TokenInfo { token: Vec::new(), atl: AuthTrustLevel::Atl0 },
            algorithm_list: Vec::new(),
            selected_algorithm: 0,
        })
    }

    fn get_request_id(&self) -> i32 {
        self.key_nego_param.request_id
    }

    fn get_key_pair(&self) -> Result<&KeyPair, ErrorCode> {
        match &self.key_nego_param.key_pair {
            Some(key_pair) => Ok(key_pair),
            None => {
                log_e!("x25519 key pair not set");
                Err(ErrorCode::GeneralError)
            },
        }
    }

    fn decode_sec_key_nego_request(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let processor_type = ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?;
        let output = SecKeyNegoRequest::decode(sec_message, processor_type)?;
        if !output.algorithm_list.contains(&(AlgoType::X25519 as u16)) {
            log_e!("algorithm list is not contain X25519");
            return Err(ErrorCode::GeneralError);
        }
        self.algorithm_list = output.algorithm_list.clone();
        Ok(())
    }

    fn encode_sec_key_nego_reply(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let key_pair = CryptoEngineRegistry::get().generate_x25519_key_pair().map_err(|e| p!(e))?;
        self.key_nego_param.key_pair = Some(key_pair.clone());

        let selected_algorithm = AlgoType::X25519 as u16;
        let key_nego_reply = Box::new(SecKeyNegoReply {
            algorithm: selected_algorithm,
            challenge: self.key_nego_param.companion_challenge,
            pub_key: key_pair.pub_key.clone(),
        });
        let output = key_nego_reply.encode(ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?)?;
        self.selected_algorithm = selected_algorithm;
        Ok(output)
    }

    fn init_device_info(&mut self) -> Result<(Box<HostBinding>, Box<HostBindingSk>), ErrorCode> {
        let binding_id = HostBindingDbManagerRegistry::get().generate_unique_binding_id().map_err(|e| p!(e))?;
        let device_info = Box::new(HostBinding {
            binding_id,
            device_key: self.key_nego_param.host_device_key.clone(),
            user_info: UserInfo { user_id: self.key_nego_param.companion_device_key.user_id, user_type: 0 },
            binding_time: TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?,
            last_used_time: 0,
        });

        let sk_info = Box::new(HostBindingSk {
            sk: self.sk.clone().try_into().map_err(|e| {
                log_e!("try_into fail: {:?}", e);
                ErrorCode::GeneralError
            })?,
        });

        Ok((device_info, sk_info))
    }

    fn decode_sec_binding_request(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let processor_type = ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?;
        let output = SecBindingRequest::decode(sec_message, processor_type)?;

        let key_pair = self.get_key_pair()?;
        let sk = CryptoEngineRegistry::get().x25519_ecdh(key_pair, &output.pub_key).map_err(|e| {
            log_e!("x25519 computation failed for processor_type: {:?}, result: {:?}", processor_type, e);
            ErrorCode::GeneralError
        })?;

        self.session_key = CryptoEngineRegistry::get().hkdf(&output.salt, &sk).map_err(|e| p!(e))?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &self.session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let device_id = decrypt_attribute.get_string(AttributeKey::AttrDeviceId).map_err(|e| p!(e))?;
        let user_id = decrypt_attribute.get_i32(AttributeKey::AttrUserId).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrCompanionChallenge).map_err(|e| p!(e))?;

        if self.key_nego_param.host_device_key.device_id != device_id {
            log_e!("device_id check fail");
            return Err(ErrorCode::GeneralError);
        }

        if self.key_nego_param.host_device_key.user_id != user_id {
            log_e!("user_id check fail, expected: {}, got: {}", self.key_nego_param.host_device_key.user_id, user_id);
            return Err(ErrorCode::GeneralError);
        }

        if self.key_nego_param.companion_challenge != challenge {
            log_e!("challenge check fail");
            return Err(ErrorCode::GeneralError);
        }

        self.binding_param.host_challenge = output.challenge;
        self.binding_param.salt = output.salt;
        self.sk = sk;
        Ok(())
    }

    fn encode_sec_binding_reply(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let reply_info = Box::new(SecBindingReplyInfo {
            device_id: self.key_nego_param.companion_device_key.device_id.clone(),
            user_id: self.key_nego_param.companion_device_key.user_id,
            esl: ExecutorSecurityLevel::Esl3 as i32,
            track_ability_level: TrackAbilityLevel::Tal4 as i32,
            challenge: self.binding_param.host_challenge,
            protocol_list: self.protocol_list.clone(),
            capability_list: self.capability_list.clone(),
        });
        let (encrypt_data, tag, iv) =
            message_crypto::encrypt_sec_message(&reply_info.encode()?, &self.session_key).map_err(|e| p!(e))?;

        let binding_reply =
            Box::new(SecBindingReply { challenge: self.key_nego_param.companion_challenge, tag, iv, encrypt_data });
        let output = binding_reply.encode(ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?)?;
        Ok(output)
    }

    fn decode_sec_token_issue(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let processor_type = ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?;
        let issue_token = SecIssueToken::decrypt_issue_token(sec_message, processor_type, &self.session_key)?;

        if issue_token.challenge != self.key_nego_param.companion_challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }

        self.token_info.token = issue_token.token.to_vec();
        self.token_info.atl = AuthTrustLevel::try_from(issue_token.atl).map_err(|_| {
            log_e!("Invalid ATL value: {}", issue_token.atl);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        let token_info = HostBindingToken {
            token: self.token_info.token.clone().try_into().map_err(|e| {
                log_e!("try_into fail: {:?}", e);
                ErrorCode::GeneralError
            })?,
            atl: self.token_info.atl,
        };

        HostBindingDbManagerRegistry::get_mut().write_device_token(self.binding_id, &token_info)?;
        Ok(())
    }

    fn store_device_info(&mut self) -> Result<(HostBinding, Option<i32>), ErrorCode> {
        let (device_info, sk_info) = self.init_device_info()?;
        let replaced_binding_id = host_binding_db_helper::add_host_binding(&device_info, &sk_info)?;
        Ok((*device_info, replaced_binding_id))
    }
}

impl Request for CompanionDeviceEnrollRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDeviceEnrollRequest prepare start");
        let RequestParam::CompanionKeyNego(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.decode_sec_key_nego_request(ffi_input.sec_message.as_slice()?)?;
        let sec_message = self.encode_sec_key_nego_reply()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        let (algo_data, algo_len) = crate::commands::common_command::try_array_from_vec(self.algorithm_list.clone())?;
        ffi_output.algorithm_list.data = algo_data;
        ffi_output.algorithm_list.len = algo_len;
        ffi_output.selected_algorithm = self.selected_algorithm;
        Ok(())
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDeviceEnrollRequest begin start");
        let RequestParam::CompanionEnrollBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.decode_sec_binding_request(ffi_input.sec_message.as_slice()?)?;

        let sec_message = self.encode_sec_binding_reply()?;
        let (device_info, replaced_binding_id) = self.store_device_info()?;
        self.binding_id = device_info.binding_id;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        ffi_output.replaced_binding_id = replaced_binding_id.unwrap_or(0);
        ffi_output.binding_status = PersistedHostBindingStatusFfi {
            binding_id: device_info.binding_id,
            companion_user_id: device_info.user_info.user_id,
            host_device_key: DeviceKeyFfi::try_from(device_info.device_key)?,
            is_token_valid: false,
        };
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDeviceEnrollRequest end start");
        let RequestParam::CompanionEnrollEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        if ffi_input.result != ErrorCode::Success as i32 {
            log_e!("result is not success");
            return Err(ErrorCode::GeneralError);
        }

        self.decode_sec_token_issue(ffi_input.sec_message.as_slice()?)?;
        self.store_token()?;
        host_binding_db_helper::update_host_binding_last_used_time(self.binding_id)?;
        ffi_output.atl = self.token_info.atl as i32;
        ffi_output.esl = ExecutorSecurityLevel::Esl3 as i32;
        Ok(())
    }
}
