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
use crate::entry::companion_device_auth_ffi::PROPERTY_MODE_UNFREEZE;
use crate::entry::companion_device_auth_ffi::{
    DataArray1024Ffi, HostBeginIssueTokenInputFfi, HostBeginIssueTokenOutputFfi,
    HostEndIssueTokenInputFfi, HostEndIssueTokenOutputFfi, HostPreIssueTokenInputFfi,
    HostPreIssueTokenOutputFfi,
};
use crate::jobs::host_db_helper;
use crate::jobs::message_crypto;
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngineRegistry};
use crate::traits::db_manager::CompanionTokenInfo;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::host_request_manager::{HostRequest, HostRequestInput, HostRequestOutput};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct PreIssueInfo {
    pub device_type: DeviceType,
    pub challenge: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct IssueTokenInfo {
    pub device_type: DeviceType,
    pub token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenIssueParam {
    pub request_id: i32,
    pub template_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct HostDeviceIssueTokenRequest {
    pub token_issue_param: TokenIssueParam,
    pub pre_issue_info: Vec<PreIssueInfo>,
    pub token_info: Vec<IssueTokenInfo>,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub atl: AuthTrustLevel,
}

impl HostDeviceIssueTokenRequest {
    pub fn new(issue_token_param: &HostPreIssueTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get()
            .secure_random(&mut salt)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

        Ok(HostDeviceIssueTokenRequest {
            token_issue_param: TokenIssueParam {
                request_id: issue_token_param.request_id,
                template_id: issue_token_param.template_id,
            },
            pre_issue_info: Vec::new(),
            token_info: Vec::new(),
            salt: salt,
            atl: AuthTrustLevel::Atl0,
        })
    }

    fn get_request_id(&self) -> i32 {
        self.token_issue_param.request_id
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
        let template_ids = attribute
            .get_u64_vec(AttributeKey::AttrTemplateIdList)
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

        if !template_ids.contains(&self.token_issue_param.template_id) {
            log_e!("template_id check fail");
            return Err(ErrorCode::GeneralError);
        }

        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;
        Ok(())
    }

    fn create_prepare_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut final_attribute = Attribute::new();

        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);

        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());

        Ok(final_attribute.to_bytes()?)
    }

    fn parse_pre_issue_reply_data(
        &mut self,
        device_type: DeviceType,
        message_data: &[u8],
    ) -> Result<(), ErrorCode> {
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

        let session_key = host_db_helper::get_session_key(
            self.token_issue_param.template_id,
            device_type,
            &self.salt,
        )?;
        let decrypt_data = message_crypto::decrypt_sec_message(encrypt_data, &session_key, tag, iv)
            .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;

        let pre_issue_info = PreIssueInfo {
            device_type,
            challenge,
        };
        self.pre_issue_info.push(pre_issue_info);
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Err(e) = self.parse_pre_issue_reply_data(DeviceType::None, value) {
                log_e!("parse common message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        if self.pre_issue_info.is_empty() {
            log_e!("pre issue token parameters found");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut final_attribute = Attribute::new();
        for pre_issue_info in &self.pre_issue_info {
            let mut token = [0u8; TOKEN_KEY_LEN];
            CryptoEngineRegistry::get()
                .secure_random(&mut token)
                .map_err(|_| {
                    log_e!("secure_random fail");
                    ErrorCode::GeneralError
                })?;

            let token_info = IssueTokenInfo {
                device_type: pre_issue_info.device_type,
                token: token.to_vec(),
            };
            self.token_info.push(token_info.clone());

            let session_key = host_db_helper::get_session_key(
                self.token_issue_param.template_id,
                pre_issue_info.device_type,
                &self.salt,
            )?;
            let mut encrypt_attribute = Attribute::new();
            encrypt_attribute.set_u64(AttributeKey::AttrChallenge, pre_issue_info.challenge);
            encrypt_attribute.set_u8_slice(AttributeKey::AttrToken, &token_info.token.clone());
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

            final_attribute
                .set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        }

        Ok(final_attribute.to_bytes()?)
    }

    fn parse_issue_token_reply_data(&mut self, message_data: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let result = attribute
            .get_i32(AttributeKey::AttrResultCode)
            .map_err(|e| p!(e))?;
        if result != 0 {
            log_e!("issue token returned error: {}", result);
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Err(e) = self.parse_issue_token_reply_data(value) {
                log_e!("parse common message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        for token_info in &self.token_info {
            let companion_token = CompanionTokenInfo {
                template_id: self.token_issue_param.template_id,
                device_type: token_info.device_type,
                token: token_info.token.clone(),
                atl: self.atl,
                added_time: TimeKeeperRegistry::get()
                    .get_rtc_time()
                    .map_err(|e| p!(e))?,
            };
            HostDbManagerRegistry::get_mut().add_token(&companion_token)?;
        }

        Ok(())
    }
}

impl HostRequest for HostDeviceIssueTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDeviceIssueTokenRequest prepare start");
        let HostRequestInput::IssueTokenPrepare(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice())?;
        let sec_message = self.create_prepare_sec_message()?;
        Ok(HostRequestOutput::IssueTokenPrepare(
            HostPreIssueTokenOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn begin(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDeviceIssueTokenRequest begin start");
        let HostRequestInput::IssueTokenBegin(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;
        let sec_message = self.create_begin_sec_message()?;
        Ok(HostRequestOutput::IssueTokenBegin(
            HostBeginIssueTokenOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn end(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDeviceIssueTokenRequest end start");
        let HostRequestInput::IssueTokenEnd(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice())?;
        self.store_token()?;
        Ok(HostRequestOutput::IssueTokenEnd(
            HostEndIssueTokenOutputFfi {
                atl: self.atl as i32,
            },
        ))
    }
}
