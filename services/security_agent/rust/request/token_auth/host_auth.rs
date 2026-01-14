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
use crate::entry::companion_device_auth_ffi::{
    DataArray1024Ffi, HostBeginTokenAuthInputFfi, HostBeginTokenAuthOutputFfi, HostEndTokenAuthInputFfi,
    HostEndTokenAuthOutputFfi,
};
use crate::jobs::host_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::SecCommonRequest;
use crate::request::token_auth::auth_message::{FwkAuthReply, FwkAuthRequest, SecAuthReply};
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngineRegistry};
use crate::traits::db_manager::CompanionTokenInfo;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::host_request_manager::{HostRequest, HostRequestParam};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

pub const TOKEN_VALID_PERIOD: u64 = 4 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq)]
pub struct AuthParam {
    pub request_id: i32,
    pub schedule_id: u64,
    pub template_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostTokenAuthRequest {
    pub auth_param: AuthParam,
    pub challenge: u64,
    pub atl: AuthTrustLevel,
    pub acl: AuthCapabilityLevel,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub device_type: DeviceType,
}

impl HostTokenAuthRequest {
    pub fn new(input: &HostBeginTokenAuthInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;

        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;

        Ok(HostTokenAuthRequest {
            auth_param: AuthParam {
                request_id: input.request_id,
                schedule_id: input.schedule_id,
                template_id: input.template_id,
            },
            challenge: u64::from_ne_bytes(challenge),
            atl: AuthTrustLevel::Atl0,
            acl: AuthCapabilityLevel::Acl0,
            salt: salt,
            device_type: DeviceType::None,
        })
    }

    fn parse_begin_fwk_message(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let output = FwkAuthRequest::decode(fwk_message)?;
        if self.auth_param.schedule_id != output.schedule_id {
            log_e!("scheduleId check fail");
            return Err(ErrorCode::GeneralError);
        }

        if !output.template_ids.contains(&self.auth_param.template_id) {
            log_e!("template_id check fail");
            return Err(ErrorCode::GeneralError);
        }

        self.atl = AuthTrustLevel::try_from(output.atl).map_err(|_| {
            log_e!("Invalid ATL value: {}", output.atl);
            ErrorCode::GeneralError
        })?;
        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let device_info = HostDbManagerRegistry::get().get_device(self.auth_param.template_id)?;
        self.device_type = if device_info.secure_protocol_id == SecureProtocolId::Default as u16 {
            DeviceType::None
        } else {
            log_e!("secure_protocol_id is not support secure_protocol_id: {}", device_info.secure_protocol_id);
            return Err(ErrorCode::GeneralError);
        };
        let token_info = HostDbManagerRegistry::get().get_token(self.auth_param.template_id, self.device_type)?;
        let current_time = TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?;
        if current_time < token_info.added_time {
            log_e!("bad time, current_time:{}, added_time:{}", current_time, token_info.added_time);
            return Err(ErrorCode::GeneralError);
        }
        if current_time - token_info.added_time > TOKEN_VALID_PERIOD {
            log_e!("token is expired, current_time:{}, added_time:{}", current_time, token_info.added_time);
            return Err(ErrorCode::GeneralError);
        }

        let session_key =
            host_db_helper::get_session_key(self.auth_param.template_id, token_info.device_type, &self.salt)?;

        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);

        let (encrypt_data, tag, iv) =
            message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), &session_key)
                .map_err(|e| p!(e))?;

        let auth_request = SecCommonRequest { salt: self.salt, tag, iv, encrypt_data };
        Ok(auth_request.encode(self.device_type)?)
    }

    fn parse_token_auth_reply(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecAuthReply::decode(sec_message, device_type)?;

        let token_info = HostDbManagerRegistry::get()
            .get_token(self.auth_param.template_id, device_type)
            .map_err(|e| p!(e))?;
        let atl = token_info.atl as i32;
        let atl_bytes = atl.to_le_bytes();
        let challenge_bytes = self.challenge.to_le_bytes();
        let mut data = Vec::with_capacity(atl_bytes.len() + challenge_bytes.len());
        data.extend_from_slice(&atl_bytes);
        data.extend_from_slice(&challenge_bytes);

        let expected_hmac = CryptoEngineRegistry::get()
            .hmac_sha256(&token_info.token, &data)
            .map_err(|e| p!(e))?;
        if output.hmac != expected_hmac.as_slice() {
            log_e!("hmac verification failed");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        if let Err(e) = self.parse_token_auth_reply(self.device_type, sec_message) {
            log_e!("parse token auth reply message fail: {:?}", e);
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_end_fwk_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let fwk_auth_reply = FwkAuthReply {
            schedule_id: self.auth_param.schedule_id,
            template_id: self.auth_param.template_id,
            result_code: 0,
            acl: AuthCapabilityLevel::Acl3 as i32,
            pin_sub_type: 0,
            remain_attempts: 0,
            lock_duration: 0,
        };
        let output = fwk_auth_reply.encode()?;
        Ok(output)
    }
}

impl HostRequest for HostTokenAuthRequest {
    fn get_request_id(&self) -> i32 {
        self.auth_param.request_id
    }

    fn prepare(&mut self, _param: HostRequestParam) -> Result<(), ErrorCode> {
        log_e!("HostTokenAuthRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: HostRequestParam) -> Result<(), ErrorCode> {
        log_i!("HostTokenAuthRequest begin start");
        let HostRequestParam::TokenAuthBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice()?)?;
        let sec_message = self.create_begin_sec_message()?;
        ffi_output.sec_message = DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?;
        Ok(())
    }

    fn end(&mut self, param: HostRequestParam) -> Result<(), ErrorCode> {
        log_i!("HostTokenAuthRequest end start");
        let HostRequestParam::TokenAuthEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice()?)?;
        let fwk_message = self.create_end_fwk_message()?;
        ffi_output.fwk_message = DataArray1024Ffi::try_from(fwk_message).map_err(|e| p!(e))?;
        Ok(())
    }
}
