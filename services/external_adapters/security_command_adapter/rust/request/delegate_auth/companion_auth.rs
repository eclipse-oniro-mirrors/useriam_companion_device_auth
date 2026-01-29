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
use crate::entry::companion_device_auth_ffi::CompanionBeginDelegateAuthInputFfi;
use crate::jobs::companion_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::{SecCommonReply, SecCommonRequest};
use crate::traits::request_manager::{Request, RequestParam};
use crate::utils::auth_token::UserAuthToken;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionDelegateAuthRequest {
    pub request_id: i32,
    pub binding_id: i32,
    pub secure_protocol_id: u16,
    pub challenge: u64,
    pub atl: AuthTrustLevel,
    pub auth_type: i32,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub session_key: Vec<u8>,
}

impl CompanionDelegateAuthRequest {
    pub fn new(input: &CompanionBeginDelegateAuthInputFfi) -> Result<Self, ErrorCode> {
        Ok(CompanionDelegateAuthRequest {
            request_id: input.request_id,
            binding_id: input.binding_id,
            secure_protocol_id: input.secure_protocol_id,
            challenge: 0,
            atl: AuthTrustLevel::Atl2,
            auth_type: 1,
            salt: [0u8; HKDF_SALT_SIZE],
            session_key: Vec::new(),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecCommonRequest::decode(
            sec_message,
            DeviceType::companion_from_secure_protocol_id(self.secure_protocol_id)?,
        )?;

        self.session_key = companion_db_helper::get_session_key(self.binding_id, &output.salt)?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &self.session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrChallenge).map_err(|e| p!(e))?;
        let atl_value = decrypt_attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;
        self.salt = output.salt;
        self.challenge = challenge;
        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn create_end_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);
        encrypt_attribute.set_i32(AttributeKey::AttrType, self.auth_type);
        encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, self.atl as i32);

        let (encrypt_data, tag, iv) =
            message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), &self.session_key)
                .map_err(|e| p!(e))?;

        let sec_auth_reply = Box::new(SecCommonReply { tag, iv, encrypt_data });
        let output = sec_auth_reply.encode(DeviceType::companion_from_secure_protocol_id(self.secure_protocol_id)?)?;
        Ok(output)
    }
}

impl Request for CompanionDelegateAuthRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("CompanionDelegateAuthRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDelegateAuthRequest begin start");
        let RequestParam::CompanionDelegateAuthBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice()?)?;

        ffi_output.challenge = self.challenge;
        ffi_output.atl = self.atl as i32;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDelegateAuthRequest end start");
        let RequestParam::CompanionDelegateAuthEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        if ffi_input.result != ErrorCode::Success as i32 {
            log_e!("delegate auth fail {}", ffi_input.result);
            return Ok(());
        }

        if ffi_input.auth_token.len as usize != core::mem::size_of::<UserAuthToken>() {
            log_e!(
                "auth_token length mismatch: expected {}, got {}",
                core::mem::size_of::<UserAuthToken>(),
                ffi_input.auth_token.len
            );
            return Err(ErrorCode::GeneralError);
        }

        let auth_token = UserAuthToken::deserialize(&ffi_input.auth_token.data[..ffi_input.auth_token.len as usize])
            .map_err(|e| p!(e))?;
        self.atl = auth_token.token_data_plain.auth_trust_level;

        let sec_message = self.create_end_sec_message()?;
        companion_db_helper::update_host_device_last_used_time(self.binding_id)?;

        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }
}
