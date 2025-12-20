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
    DataArray1024Ffi, HostBeginDelegateAuthInputFfi, HostBeginDelegateAuthOutputFfi,
    HostBeginTokenAuthInputFfi, HostBeginTokenAuthOutputFfi, HostEndDelegateAuthInputFfi,
    HostEndDelegateAuthOutputFfi, HostEndTokenAuthInputFfi, HostEndTokenAuthOutputFfi,
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

pub const TOKEN_VALID_PERIOD: u64 = 4 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthParam {
    pub request_id: i32,
    pub schedule_id: u64,
    pub template_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct HostTokenAuthRequest {
    pub auth_param: AuthParam,
    pub challenge: u64,
    pub atl: AuthTrustLevel,
    pub acl: AuthCapabilityLevel,
    pub salt: [u8; HKDF_SALT_SIZE],
}

impl HostTokenAuthRequest {
    pub fn new(input: &HostBeginTokenAuthInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get()
            .secure_random(&mut challenge)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get()
            .secure_random(&mut salt)
            .map_err(|_| {
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
        })
    }

    fn parse_begin_fwk_message(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let pub_key = MiscManagerRegistry::get_mut()
            .get_fwk_pub_key()
            .map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
        let attribute = message_codec
            .deserialize_attribute(fwk_message)
            .map_err(|e| p!(e))?;

        let schedule_id = attribute
            .get_u64(AttributeKey::AttrScheduleId)
            .map_err(|e| p!(e))?;
        let template_ids = attribute
            .get_u64_vec(AttributeKey::AttrTemplateIdList)
            .map_err(|e| p!(e))?;
        let atl_value = attribute
            .get_i32(AttributeKey::AttrAuthTrustLevel)
            .map_err(|e| p!(e))?;

        if self.auth_param.schedule_id != schedule_id {
            log_e!("scheduleId check fail");
            return Err(ErrorCode::GeneralError);
        }

        if !template_ids.contains(&self.auth_param.template_id) {
            log_e!("template_id check fail");
            return Err(ErrorCode::GeneralError);
        }

        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;
        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        host_db_helper::get_companion_device(self.auth_param.template_id)?;

        let token_info = HostDbManagerRegistry::get()
            .get_token(self.auth_param.template_id, DeviceType::None)?;
        let current_time = TimeKeeperRegistry::get()
            .get_rtc_time()
            .map_err(|e| p!(e))?;
        if current_time < token_info.added_time {
            log_e!(
                "bad time, current_time:{}, added_time:{}",
                current_time,
                token_info.added_time
            );
            return Err(ErrorCode::GeneralError);
        }
        if current_time - token_info.added_time > TOKEN_VALID_PERIOD {
            log_e!(
                "token is expired, current_time:{}, added_time:{}",
                current_time,
                token_info.added_time
            );
            return Err(ErrorCode::GeneralError);
        }

        let session_key = host_db_helper::get_session_key(
            self.auth_param.template_id,
            token_info.device_type,
            &self.salt,
        )?;

        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);

        let (encrypt_data, tag, iv) = message_crypto::encrypt_sec_message(
            encrypt_attribute.to_bytes()?.as_slice(),
            &session_key,
        )
        .map_err(|e| p!(e))?;

        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);
        attribute.set_u8_slice(AttributeKey::AttrTag, &tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        Ok(final_attribute.to_bytes()?)
    }

    fn parse_token_auth_reply_data(
        &mut self,
        device_type: DeviceType,
        message_data: &[u8],
    ) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let mac = attribute
            .get_u8_slice(AttributeKey::AttrHmac)
            .map_err(|e| p!(e))?;
        let token_info = HostDbManagerRegistry::get()
            .get_token(self.auth_param.template_id, device_type)
            .map_err(|e| p!(e))?;
        let expected_mac = CryptoEngineRegistry::get()
            .hmac_sha256(&token_info.token, &self.challenge.to_ne_bytes())
            .map_err(|e| p!(e))?;
        if mac != expected_mac.as_slice() {
            log_e!("hmac verification failed");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;

        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Err(e) = self.parse_token_auth_reply_data(DeviceType::None, value) {
                log_e!("parse common message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn create_end_fwk_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u64(AttributeKey::AttrScheduleId, self.auth_param.schedule_id);
        attribute.set_i32(AttributeKey::AttrResultCode, 0);
        attribute.set_i32(
            AttributeKey::AttrCapabilityLevel,
            AuthCapabilityLevel::Acl3 as i32,
        );
        attribute.set_u64(AttributeKey::AttrTemplateId, self.auth_param.template_id);
        attribute.set_u64(AttributeKey::AttrPinSubType, 0);
        attribute.set_i32(AttributeKey::AttrRemainAttempts, 0);
        attribute.set_i32(AttributeKey::AttrLockoutDuration, 0);

        let local_key_pair = MiscManagerRegistry::get_mut()
            .get_local_key_pair()
            .map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Executor(local_key_pair));
        let fwk_message = message_codec
            .serialize_attribute(&attribute)
            .map_err(|e| p!(e))?;
        Ok(fwk_message)
    }
}

impl HostRequest for HostTokenAuthRequest {
    fn get_request_id(&self) -> i32 {
        self.auth_param.request_id
    }

    fn prepare(&mut self, _input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_e!("HostTokenAuthRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostTokenAuthRequest begin start");
        let HostRequestInput::TokenAuthBegin(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice())?;
        let sec_message = self.create_begin_sec_message()?;

        Ok(HostRequestOutput::TokenAuthBegin(
            HostBeginTokenAuthOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn end(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostTokenAuthRequest end start");
        let HostRequestInput::TokenAuthEnd(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice())?;
        let fwk_message = self.create_end_fwk_message()?;

        Ok(HostRequestOutput::TokenAuthEnd(HostEndTokenAuthOutputFfi {
            fwk_message: DataArray1024Ffi::try_from(fwk_message).map_err(|e| p!(e))?,
        }))
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct HostDelegateAuthRequest {
    pub auth_param: AuthParam,
    pub challenge: u64,
    pub atl: AuthTrustLevel,
    pub acl: AuthCapabilityLevel,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub auth_type: i32,
}

impl HostDelegateAuthRequest {
    pub fn new(input: &HostBeginDelegateAuthInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get()
            .secure_random(&mut challenge)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get()
            .secure_random(&mut salt)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

        Ok(HostDelegateAuthRequest {
            auth_param: AuthParam {
                request_id: input.request_id,
                schedule_id: input.schedule_id,
                template_id: input.template_id,
            },
            challenge: u64::from_ne_bytes(challenge),
            atl: AuthTrustLevel::Atl2,
            acl: AuthCapabilityLevel::Acl0,
            salt: salt,
            auth_type: 0,
        })
    }

    fn parse_begin_fwk_message(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let pub_key = MiscManagerRegistry::get_mut()
            .get_fwk_pub_key()
            .map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
        let attribute = message_codec
            .deserialize_attribute(fwk_message)
            .map_err(|e| p!(e))?;

        let schedule_id = attribute
            .get_u64(AttributeKey::AttrScheduleId)
            .map_err(|e| p!(e))?;

        let atl_value = attribute
            .get_i32(AttributeKey::AttrAuthTrustLevel)
            .map_err(|e| p!(e))?;

        if self.auth_param.schedule_id != schedule_id {
            log_e!("scheduleId check fail");
            return Err(ErrorCode::GeneralError);
        }

        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let session_key = host_db_helper::get_session_key(
            self.auth_param.template_id,
            DeviceType::None,
            &self.salt,
        )?;
        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);
        encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, self.atl as i32);

        let (encrypt_data, tag, iv) = message_crypto::encrypt_sec_message(
            encrypt_attribute.to_bytes()?.as_slice(),
            &session_key,
        )
        .map_err(|e| p!(e))?;

        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);
        attribute.set_u8_slice(AttributeKey::AttrTag, &tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        Ok(final_attribute.to_bytes()?)
    }

    fn parse_auth_reply_data(
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

        let session_key =
            host_db_helper::get_session_key(self.auth_param.template_id, device_type, &self.salt)?;
        let decrypt_data = message_crypto::decrypt_sec_message(encrypt_data, &session_key, tag, iv)
            .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let auth_type = decrypt_attribute
            .get_i32(AttributeKey::AttrType)
            .map_err(|e| p!(e))?;
        let atl_value = decrypt_attribute
            .get_i32(AttributeKey::AttrAuthTrustLevel)
            .map_err(|e| p!(e))?;
        let challenge = decrypt_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;
        if challenge != self.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }

        self.auth_type = auth_type;
        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Err(e) = self.parse_auth_reply_data(DeviceType::None, value) {
                log_e!("parse common message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn create_end_fwk_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u64(AttributeKey::AttrScheduleId, self.auth_param.schedule_id);
        attribute.set_i32(AttributeKey::AttrResultCode, 0);
        attribute.set_i32(
            AttributeKey::AttrCapabilityLevel,
            AuthCapabilityLevel::Acl3 as i32,
        );
        attribute.set_u64(AttributeKey::AttrTemplateId, self.auth_param.template_id);
        attribute.set_u64(AttributeKey::AttrPinSubType, 0);
        attribute.set_i32(AttributeKey::AttrRemainAttempts, 0);
        attribute.set_i32(AttributeKey::AttrLockoutDuration, 0);

        let local_key_pair = MiscManagerRegistry::get_mut()
            .get_local_key_pair()
            .map_err(|e| p!(e))?;
        let message_codec = MessageCodec::new(MessageSignParam::Executor(local_key_pair));
        let fwk_message = message_codec
            .serialize_attribute(&attribute)
            .map_err(|e| p!(e))?;
        Ok(fwk_message)
    }
}

impl HostRequest for HostDelegateAuthRequest {
    fn get_request_id(&self) -> i32 {
        self.auth_param.request_id
    }

    fn prepare(&mut self, _input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_e!("HostDelegateAuthRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDelegateAuthRequest begin start");
        let HostRequestInput::DelegateAuthBegin(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice())?;
        let sec_message = self.create_begin_sec_message()?;

        Ok(HostRequestOutput::DelegateAuthBegin(
            HostBeginDelegateAuthOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn end(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDelegateAuthRequest end start");
        let HostRequestInput::DelegateAuthEnd(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice())?;
        let fwk_message = self.create_end_fwk_message()?;

        Ok(HostRequestOutput::DelegateAuthEnd(
            HostEndDelegateAuthOutputFfi {
                fwk_message: DataArray1024Ffi::try_from(fwk_message).map_err(|e| p!(e))?,
                auth_type: self.auth_type,
                atl: self.atl as i32,
            },
        ))
    }
}
