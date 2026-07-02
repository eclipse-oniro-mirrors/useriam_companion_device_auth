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
use crate::entry::companion_device_auth_ffi::CompanionPreIssueTokenInputFfi;
use crate::jobs::host_binding_db_helper;
use crate::request::jobs::common_message::SecIssueToken;
use crate::request::token_issue::token_issue_message::{SecIssueTokenReply, SecPreIssueReply, SecPreIssueRequest};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::HostBindingToken;
use crate::traits::host_binding_db_manager::HostBindingDbManagerRegistry;
use crate::traits::log_trace::RustFileId;
use crate::traits::request_manager::{Request, RequestParam};
use crate::{log_e, log_i, Box, Vec};
pub(crate) const FILE_ID: u16 = RustFileId::CompanionIssueToken as u16;
#[derive(Debug, Clone, PartialEq)]
pub struct PreIssueParam {
    pub salt: [u8; HKDF_SALT_SIZE],
    pub companion_challenge: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenInfo {
    pub token: Vec<u8>,
    pub atl: AuthTrustLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionDeviceIssueTokenRequest {
    pub request_id: i32,
    pub binding_id: i32,
    pub secure_protocol_id: u16,
    pub pre_issue_param: PreIssueParam,
    pub token_info: TokenInfo,
    pub session_key: Vec<u8>,
}

impl CompanionDeviceIssueTokenRequest {
    pub fn new(input: &CompanionPreIssueTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random challenge fail");
            ErrorCode::GeneralError
        })?;

        Ok(CompanionDeviceIssueTokenRequest {
            request_id: input.request_id,
            binding_id: input.binding_id,
            secure_protocol_id: input.secure_protocol_id,
            pre_issue_param: PreIssueParam {
                salt: [0u8; HKDF_SALT_SIZE],
                companion_challenge: u64::from_ne_bytes(challenge),
            },
            token_info: TokenInfo { token: Vec::new(), atl: AuthTrustLevel::Atl0 },
            session_key: Vec::new(),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn decode_sec_token_pre_issue_request(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let processor_type = ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?;
        let output = SecPreIssueRequest::decode(sec_message, processor_type)?;
        self.pre_issue_param.salt = output.salt;
        Ok(())
    }

    fn encode_sec_token_pre_issue_reply(&mut self) -> Result<Vec<u8>, ErrorCode> {
        self.session_key = host_binding_db_helper::get_session_key(self.binding_id, &self.pre_issue_param.salt)?;
        let sec_pre_issue_reply = Box::new(SecPreIssueReply { challenge: self.pre_issue_param.companion_challenge });
        let output = sec_pre_issue_reply.encode(ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?)?;
        Ok(output)
    }

    fn decode_sec_token_issue_request(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let processor_type = ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?;
        let issue_token = SecIssueToken::decrypt_issue_token(sec_message, processor_type, &self.session_key)?;

        if issue_token.challenge != self.pre_issue_param.companion_challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }

        self.token_info = TokenInfo {
            token: issue_token.token,
            atl: AuthTrustLevel::try_from(issue_token.atl).map_err(|_| {
                log_e!("Invalid ATL value: {}", issue_token.atl);
                ErrorCode::GeneralError
            })?,
        };
        Ok(())
    }

    fn encode_sec_token_issue_reply(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let issue_token_reply = Box::new(SecIssueTokenReply { result: ErrorCode::Success as i32 });
        let output = issue_token_reply.encode(ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?)?;
        Ok(output)
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
}

impl Request for CompanionDeviceIssueTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("CompanionDeviceIssueTokenRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDeviceIssueTokenRequest begin start");
        let RequestParam::CompanionIssueTokenBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.decode_sec_token_pre_issue_request(ffi_input.sec_message.as_slice()?)?;

        let sec_message = self.encode_sec_token_pre_issue_reply()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDeviceIssueTokenRequest end start");
        let RequestParam::CompanionIssueTokenEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.decode_sec_token_issue_request(ffi_input.sec_message.as_slice()?)?;

        let sec_message = self.encode_sec_token_issue_reply()?;
        self.store_token()?;

        ffi_output.atl = self.token_info.atl as i32;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }
}
