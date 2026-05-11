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
    AuthCapabilityLevel, AuthTrustLevel, Capability, ErrorCode, ProcessorType, SecureProtocolId, CHALLENGE_LEN,
    HKDF_SALT_SIZE,
};
use crate::entry::companion_device_auth_ffi::HostBeginTokenAuthInputFfi;
use crate::jobs::companion_device_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::SecCommonRequest;
use crate::request::token_auth::token_auth_message::{FwkAuthReply, FwkAuthRequest, SecAuthReply};
use crate::traits::companion_device_db_manager::CompanionDeviceDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};
use crate::traits::log_trace::RustFileId;
pub(crate) const FILE_ID: u16 = RustFileId::HostTokenAuth as u16;
pub const TOKEN_VALID_PERIOD: u64 = 4 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq)]
pub struct AuthParam {
    pub request_id: i32,
    pub schedule_id: u64,
    pub template_id: u64,
    pub secure_protocol_id: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostTokenAuthRequest {
    pub auth_param: AuthParam,
    pub host_challenge: u64,
    pub atl: AuthTrustLevel,
    pub acl: AuthCapabilityLevel,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub processor_type: ProcessorType,
}

impl HostTokenAuthRequest {
    pub fn new(input: &HostBeginTokenAuthInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random challenge fail");
            ErrorCode::GeneralError
        })?;

        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
            log_e!("secure_random salt fail");
            ErrorCode::GeneralError
        })?;

        Ok(HostTokenAuthRequest {
            auth_param: AuthParam {
                request_id: input.request_id,
                schedule_id: input.schedule_id,
                template_id: input.template_id,
                secure_protocol_id: input.secure_protocol_id,
            },
            host_challenge: u64::from_ne_bytes(challenge),
            atl: AuthTrustLevel::Atl0,
            acl: AuthCapabilityLevel::Acl0,
            salt,
            processor_type: ProcessorType::default(),
        })
    }

    fn decode_fwk_token_auth_request(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
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

    fn encode_sec_token_auth_request(&mut self) -> Result<Vec<u8>, ErrorCode> {
        self.processor_type = if self.auth_param.secure_protocol_id == SecureProtocolId::Default as u16 {
            self.acl = AuthCapabilityLevel::Acl3;
            ProcessorType::default()
        } else {
            log_e!("secure_protocol_id is not supported: {}", self.auth_param.secure_protocol_id);
            return Err(ErrorCode::GeneralError);
        };
        let token_info =
            CompanionDeviceDbManagerRegistry::get().get_token(self.auth_param.template_id, self.processor_type)?;
        let current_time = TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?;
        if let Some(time_period) = current_time.checked_sub(token_info.added_time) {
            if time_period > TOKEN_VALID_PERIOD {
                log_e!("token is expired, current_time:{}, added_time:{}", current_time, token_info.added_time);
                return Err(ErrorCode::Timeout);
            }
        } else {
            log_e!("bad time, current_time:{}, added_time:{}", current_time, token_info.added_time);
            return Err(ErrorCode::GeneralError);
        }

        let session_key = companion_device_db_helper::get_session_key(
            self.auth_param.template_id,
            token_info.processor_type,
            &self.salt,
        )?;

        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrHostChallenge, self.host_challenge);

        let (encrypt_data, tag, iv) =
            message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), &session_key)
                .map_err(|e| p!(e))?;

        let auth_request = Box::new(SecCommonRequest { salt: self.salt, tag, iv, encrypt_data });
        auth_request.encode(self.processor_type)
    }

    fn decode_sec_token_auth_reply_message(
        &mut self,
        processor_type: ProcessorType,
        sec_message: &[u8],
    ) -> Result<(), ErrorCode> {
        let output = SecAuthReply::decode(sec_message, processor_type)?;

        let token_info = CompanionDeviceDbManagerRegistry::get()
            .get_token(self.auth_param.template_id, processor_type)
            .map_err(|e| p!(e))?;
        let atl = token_info.atl as i32;
        let atl_bytes = atl.to_le_bytes();
        let challenge_bytes = self.host_challenge.to_le_bytes();
        let mut data = Vec::with_capacity(atl_bytes.len() + challenge_bytes.len());
        data.extend_from_slice(&atl_bytes);
        data.extend_from_slice(&challenge_bytes);

        let expected_hmac = CryptoEngineRegistry::get().hmac_sha256(&token_info.token, &data).map_err(|e| p!(e))?;
        if output.hmac.len() != expected_hmac.len() {
            log_e!("mac len not match, {}:{}", output.hmac.len(), expected_hmac.len());
            return Err(ErrorCode::Fail);
        }
        let mut result = 0u8;
        for (x, y) in output.hmac.iter().zip(expected_hmac.iter()) {
            result |= x ^ y;
        }

        if result != 0 {
            log_e!("hmac verification failed");
            return Err(ErrorCode::TokenVerifyFailed);
        }

        Ok(())
    }

    fn decode_sec_token_auth_reply(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        if let Err(e) = self.decode_sec_token_auth_reply_message(self.processor_type, sec_message) {
            log_e!("parse token auth reply message fail: processor_type: {:?}, result: {:?}", self.processor_type, e);
            return Err(e);
        }

        Ok(())
    }

    fn encode_fwk_token_auth_reply(&mut self, result: ErrorCode) -> Result<Vec<u8>, ErrorCode> {
        let fwk_auth_reply = Box::new(FwkAuthReply {
            schedule_id: self.auth_param.schedule_id,
            template_id: self.auth_param.template_id,
            result_code: result as i32,
            acl: self.acl as i32,
            pin_sub_type: 0,
            remain_attempts: i32::MAX,
            lock_duration: 0,
        });
        let output = fwk_auth_reply.encode()?;
        Ok(output)
    }
}

impl Request for HostTokenAuthRequest {
    fn get_request_id(&self) -> i32 {
        self.auth_param.request_id
    }

    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("HostTokenAuthRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostTokenAuthRequest begin start");
        let RequestParam::HostTokenAuthBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        companion_device_db_helper::check_device_capability(self.auth_param.template_id, Capability::TokenAuth)?;

        self.decode_fwk_token_auth_request(ffi_input.fwk_message.as_slice()?)?;
        let sec_message = self.encode_sec_token_auth_request()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostTokenAuthRequest end start");
        let RequestParam::HostTokenAuthEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        let result = match self.decode_sec_token_auth_reply(ffi_input.sec_message.as_slice()?) {
            Ok(_) => ErrorCode::Success,
            Err(result) => {
                log_e!("decode secure token auth reply fail: {:?}", result);
                result
            },
        };
        let fwk_message = self.encode_fwk_token_auth_reply(result)?;
        ffi_output.fwk_message.copy_from_vec(&fwk_message)?;
        if result != ErrorCode::Success {
            return Err(result);
        }
        Ok(())
    }
}
