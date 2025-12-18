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
    CompanionBeginObtainTokenInputFfi, CompanionBeginObtainTokenOutputFfi,
    CompanionEndObtainTokenInputFfi, CompanionEndObtainTokenOutputFfi, DataArray1024Ffi,
};

use crate::entry::companion_device_auth_ffi::PROPERTY_MODE_UNFREEZE;
use crate::jobs::companion_db_helper;
use crate::jobs::message_crypto;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::companion_request_manager::{
    CompanionRequest, CompanionRequestInput, CompanionRequestOutput,
};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::HostTokenInfo;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::message_codec::MessageCodec;
use crate::utils::message_codec::MessageSignParam;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct ObtainParam {
    pub salt: [u8; HKDF_SALT_SIZE],
    pub challenge: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct CompanionDeviceObtainTokenRequest {
    pub request_id: i32,
    pub binding_id: i32,
    pub obtain_param: ObtainParam,
    pub token: Vec<u8>,
    pub atl: AuthTrustLevel,
    pub session_key: Vec<u8>,
}

impl CompanionDeviceObtainTokenRequest {
    pub fn new(input: &CompanionBeginObtainTokenInputFfi) -> Result<Self, ErrorCode> {
        Ok(CompanionDeviceObtainTokenRequest {
            request_id: input.request_id,
            binding_id: input.binding_id,
            obtain_param: ObtainParam {
                salt: [0u8; HKDF_SALT_SIZE],
                challenge: 0,
            },
            token: Vec::new(),
            atl: AuthTrustLevel::Atl0,
            session_key: Vec::new(),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn parse_begin_fwk_message(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let pub_key = MiscManagerRegistry::get_mut()
            .get_fwk_pub_key()
            .map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
        let attribute = message_codec
            .deserialize_attribute(fwk_message)
            .map_err(|e| p!(e))?;
        let property_mode = attribute
            .get_u32(AttributeKey::AttrProperyMode)
            .map_err(|e| p!(e))?;
        let auth_type = attribute
            .get_u32(AttributeKey::AttrType)
            .map_err(|e| p!(e))?;
        let atl_value = attribute
            .get_i32(AttributeKey::AttrAuthTrustLevel)
            .map_err(|e| p!(e))?;

        if property_mode != PROPERTY_MODE_UNFREEZE {
            log_i!("property_mode is not unfreeze: {}", property_mode);
            return Ok(());
        }

        if auth_type != AuthType::Pin as u32
            && auth_type != AuthType::Face as u32
            && auth_type != AuthType::Fingerprint as u32
        {
            log_i!("auth_type is not pin or face or fingerprint: {}", auth_type);
            return Ok(());
        }

        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;
        Ok(())
    }

    fn parse_pre_obtain_reply_data(&mut self, message_data: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let salt = attribute
            .get_u8_slice(AttributeKey::AttrSalt)
            .map_err(|e| p!(e))?;
        let challenge = attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;
        self.obtain_param.salt.copy_from_slice(salt);
        self.obtain_param.challenge = challenge;
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Ok(()) = self.parse_pre_obtain_reply_data(value) {
                return Ok(());
            }
        }

        log_e!("No valid obtain message found in sec_message");
        Err(ErrorCode::GeneralError)
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let session_key =
            companion_db_helper::get_session_key(self.binding_id, &self.obtain_param.salt)?;
        self.session_key = session_key.clone();

        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.obtain_param.challenge);
        encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, self.atl as i32);

        let (encrypt_data, tag, iv) = message_crypto::encrypt_sec_message(
            encrypt_attribute.to_bytes()?.as_slice(),
            &session_key,
        )
        .map_err(|e| p!(e))?;

        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrTag, &tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());

        Ok(final_attribute.to_bytes()?)
    }

    fn parse_obtain_token_reply_data(&mut self, message_data: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let tag = attribute
            .get_u8_slice(AttributeKey::AttrTag)
            .map_err(|e| p!(e))?;
        let iv = attribute
            .get_u8_slice(AttributeKey::AttrIv)
            .map_err(|e| p!(e))?;
        let encrypt_data = attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        let decrypt_data =
            message_crypto::decrypt_sec_message(encrypt_data, &self.session_key, tag, iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;

        let challenge = decrypt_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;
        if challenge != self.obtain_param.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }

        let token = decrypt_attribute
            .get_u8_slice(AttributeKey::AttrToken)
            .map_err(|e| p!(e))?;
        let atl_value = decrypt_attribute
            .get_i32(AttributeKey::AttrAuthTrustLevel)
            .map_err(|e| p!(e))?;

        self.token = token.to_vec();
        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Ok(()) = self.parse_obtain_token_reply_data(value) {
                return Ok(());
            }
        }

        log_e!("No valid obtain token message found in sec_message");
        Err(ErrorCode::GeneralError)
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        let token_info = HostTokenInfo {
            token: self.token.clone(),
            atl: self.atl,
        };

        CompanionDbManagerRegistry::get_mut().write_token_db(self.binding_id, &token_info)?;
        Ok(())
    }
}

impl CompanionRequest for CompanionDeviceObtainTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(
        &mut self,
        _input: CompanionRequestInput,
    ) -> Result<CompanionRequestOutput, ErrorCode> {
        log_e!("CompanionDeviceObtainTokenRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceObtainTokenRequest begin start");
        let CompanionRequestInput::ObtainTokenBegin(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice())?;
        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;

        let sec_message = self.create_begin_sec_message()?;
        Ok(CompanionRequestOutput::ObtainTokenBegin(
            CompanionBeginObtainTokenOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn end(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceObtainTokenRequest end start");
        let CompanionRequestInput::ObtainTokenEnd(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice())?;
        self.store_token()?;

        companion_db_helper::update_host_device_token_valid_flag(self.binding_id, true)?;
        Ok(CompanionRequestOutput::ObtainTokenEnd(
            CompanionEndObtainTokenOutputFfi::default(),
        ))
    }
}
