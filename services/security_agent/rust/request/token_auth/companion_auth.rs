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
    CompanionProcessTokenAuthInputFfi, CompanionProcessTokenAuthOutputFfi, DataArray1024Ffi,
};
use crate::jobs::companion_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::SecCommonRequest;
use crate::request::token_auth::auth_message::SecAuthReply;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::HostTokenInfo;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionTokenAuthRequest {
    pub binding_id: i32,
    pub challenge: u64,
    pub salt: [u8; HKDF_SALT_SIZE],
}

impl CompanionTokenAuthRequest {
    pub fn new(input: &CompanionProcessTokenAuthInputFfi) -> Result<Self, ErrorCode> {
        Ok(CompanionTokenAuthRequest { binding_id: input.binding_id, challenge: 0, salt: [0u8; HKDF_SALT_SIZE] })
    }

    fn get_request_id(&self) -> i32 {
        self.binding_id
    }

    fn parse_device_auth_request(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecCommonRequest::decode(sec_message, device_type)?;

        let session_key = companion_db_helper::get_session_key(self.binding_id, &output.salt)?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrChallenge).map_err(|e| p!(e))?;

        self.challenge = challenge;
        self.salt = output.salt;
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        if let Err(e) = self.parse_device_auth_request(DeviceType::None, sec_message) {
            log_e!("parse device auth fail: {:?}", e);
            return Err(ErrorCode::GeneralError);
        }
        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let token_info = CompanionDbManagerRegistry::get_mut()
            .read_device_token(self.binding_id)
            .map_err(|e| p!(e))?;
        let atl = token_info.atl as i32;
        let atl_bytes = atl.to_le_bytes();
        let challenge_bytes = self.challenge.to_le_bytes();
        let mut data = Vec::with_capacity(atl_bytes.len() + challenge_bytes.len());
        data.extend_from_slice(&atl_bytes);
        data.extend_from_slice(&challenge_bytes);

        let hmac = CryptoEngineRegistry::get()
            .hmac_sha256(&token_info.token, &data)
            .map_err(|e| p!(e))?;

        let sec_auth_reply = SecAuthReply { hmac: hmac.to_vec() };
        let output = sec_auth_reply.encode(DeviceType::None)?;
        Ok(output)
    }
}

impl Request for CompanionTokenAuthRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("CompanionTokenAuthRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionTokenAuthRequest begin start");
        let RequestParam::CompanionTokenAuthBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice()?)?;
        let sec_message = self.create_begin_sec_message()?;

        ffi_output.sec_message = DataArray1024Ffi::try_from(sec_message).map_err(|_| {
            log_e!("sec_message try from fail");
            ErrorCode::GeneralError
        })?;
        Ok(())
    }

    fn end(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("CompanionTokenAuthRequest end not implemented");
        Err(ErrorCode::GeneralError)
    }
}
