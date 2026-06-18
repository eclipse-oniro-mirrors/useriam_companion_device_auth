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

use crate::common::constants::{AuthTrustLevel, ErrorCode, ProcessorType, CHALLENGE_LEN, HKDF_SALT_SIZE};
use crate::entry::companion_device_auth_ffi::{CompanionBeginObtainTokenInputFfi, CompanionEndObtainTokenOutputFfi};
use crate::jobs::host_binding_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::SecIssueToken;
use crate::request::jobs::fwk_msg_validator::decode_and_validate_fwk_msg;
use crate::request::token_obtain::token_obtain_message::{SecPreObtainTokenReply, SecPreObtainTokenRequest};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::HostBindingToken;
use crate::traits::host_binding_db_manager::HostBindingDbManagerRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};
use crate::traits::log_trace::RustFileId;
pub(crate) const FILE_ID: u16 = RustFileId::CompanionObtainToken as u16;
#[derive(Debug, Clone, PartialEq)]
pub struct ObtainParam {
    pub salt: [u8; HKDF_SALT_SIZE],
    pub host_challenge: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionDeviceObtainTokenRequest {
    pub request_id: i32,
    pub binding_id: i32,
    pub secure_protocol_id: u16,
    pub obtain_param: ObtainParam,
    pub token: Vec<u8>,
    pub companion_challenge: u64,
    pub atl: AuthTrustLevel,
    pub session_key: Vec<u8>,
}

impl CompanionDeviceObtainTokenRequest {
    pub fn new(input: &CompanionBeginObtainTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random challenge fail");
            ErrorCode::GeneralError
        })?;

        Ok(CompanionDeviceObtainTokenRequest {
            request_id: input.request_id,
            binding_id: input.binding_id,
            secure_protocol_id: input.secure_protocol_id,
            obtain_param: ObtainParam { salt: [0u8; HKDF_SALT_SIZE], host_challenge: 0 },
            token: Vec::new(),
            companion_challenge: u64::from_ne_bytes(challenge),
            atl: AuthTrustLevel::Atl0,
            session_key: Vec::new(),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn decode_fwk_token_obtain_request(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let fwk_msg_info = decode_and_validate_fwk_msg(fwk_message, None)?;
        self.atl = fwk_msg_info.atl;
        Ok(())
    }

    fn decode_sec_token_pre_obtain_request(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let processor_type = ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?;
        let output = SecPreObtainTokenRequest::decode(sec_message, processor_type)?;
        if output.salt.len() != HKDF_SALT_SIZE {
            log_e!("salt len is err: {}", output.salt.len());
            return Err(ErrorCode::GeneralError);
        }
        self.obtain_param.salt = output.salt;
        self.obtain_param.host_challenge = output.challenge;
        Ok(())
    }

    fn encode_sec_token_obtain_request(&mut self) -> Result<Vec<u8>, ErrorCode> {
        self.session_key = host_binding_db_helper::get_session_key(self.binding_id, &self.obtain_param.salt)?;

        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrHostChallenge, self.obtain_param.host_challenge);
        encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, self.atl as i32);

        let (encrypt_data, tag, iv) =
            message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), &self.session_key)
                .map_err(|e| p!(e))?;

        let pre_obtain_token_reply =
            Box::new(SecPreObtainTokenReply { challenge: self.companion_challenge, tag, iv, encrypt_data });
        let output = pre_obtain_token_reply.encode(ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?)?;
        Ok(output)
    }

    fn parse_obtain_token_reply(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let processor_type = ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?;
        let issue_token = SecIssueToken::decrypt_issue_token(sec_message, processor_type, &self.session_key)?;

        if issue_token.challenge != self.companion_challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }

        self.token = issue_token.token.to_vec();
        self.atl = AuthTrustLevel::try_from(issue_token.atl).map_err(|_| {
            log_e!("Invalid ATL value: {}", issue_token.atl);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        let token_info = HostBindingToken {
            token: self.token.clone().try_into().map_err(|e| {
                log_e!("try_into fail: {:?}", e);
                ErrorCode::GeneralError
            })?,
            atl: self.atl,
        };

        HostBindingDbManagerRegistry::get_mut().write_device_token(self.binding_id, &token_info)?;
        Ok(())
    }
}

impl Request for CompanionDeviceObtainTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("CompanionDeviceObtainTokenRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDeviceObtainTokenRequest begin start");
        let RequestParam::CompanionObtainTokenBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.decode_fwk_token_obtain_request(ffi_input.fwk_message.as_slice()?)?;
        self.decode_sec_token_pre_obtain_request(ffi_input.sec_message.as_slice()?)?;

        let sec_message = self.encode_sec_token_obtain_request()?;
        ffi_output.atl = self.atl as i32;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDeviceObtainTokenRequest end start");
        let RequestParam::CompanionObtainTokenEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_obtain_token_reply(ffi_input.sec_message.as_slice()?)?;
        self.store_token()?;

        *ffi_output = CompanionEndObtainTokenOutputFfi::default();
        Ok(())
    }
}
