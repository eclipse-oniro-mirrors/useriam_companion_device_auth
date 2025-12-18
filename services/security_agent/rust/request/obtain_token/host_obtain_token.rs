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
    DataArray1024Ffi, HostProcessObtainTokenInputFfi, HostProcessObtainTokenOutputFfi,
    HostProcessPreObtainTokenInputFfi, HostProcessPreObtainTokenOutputFfi,
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
use crate::vec;
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct ObtainTokenInfo {
    pub device_type: DeviceType,
    pub atl: AuthTrustLevel,
    pub token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenObtainParam {
    pub request_id: i32,
    pub template_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct HostDeviceObtainTokenRequest {
    pub obtain_param: TokenObtainParam,
    pub token_infos: Vec<ObtainTokenInfo>,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub challenge: u64,
}

impl HostDeviceObtainTokenRequest {
    pub fn new(input: &HostProcessPreObtainTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get()
            .secure_random(&mut salt)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get()
            .secure_random(&mut challenge)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;
        Ok(HostDeviceObtainTokenRequest {
            obtain_param: TokenObtainParam {
                request_id: input.request_id,
                template_id: input.template_id,
            },
            token_infos: Vec::new(),
            salt: salt,
            challenge: u64::from_ne_bytes(challenge),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.obtain_param.request_id
    }

    fn create_prepare_sec_message(&self) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);
        attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        Ok(final_attribute.to_bytes()?)
    }

    fn parse_obtain_token_requset_data(
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
            self.obtain_param.template_id,
            device_type,
            &self.salt,
        )?;
        let decrypt_data = message_crypto::decrypt_sec_message(encrypt_data, &session_key, tag, iv)
            .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;
        if challenge != self.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }
        let atl_value = decrypt_attribute
            .get_i32(AttributeKey::AttrAuthTrustLevel)
            .map_err(|e| p!(e))?;
        let atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        let mut token = [0u8; TOKEN_KEY_LEN];
        CryptoEngineRegistry::get()
            .secure_random(&mut token)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

        let token_info = ObtainTokenInfo {
            device_type,
            atl,
            token: token.to_vec(),
        };
        self.token_infos.push(token_info);
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Err(e) = self.parse_obtain_token_requset_data(DeviceType::None, value) {
                log_e!("parse common message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        if self.token_infos.is_empty() {
            log_e!("obtain token parameters found");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let token_info = &self.token_infos[0];
        let session_key = host_db_helper::get_session_key(
            self.obtain_param.template_id,
            token_info.device_type,
            &self.salt,
        )?;
        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);
        encrypt_attribute.set_u8_slice(AttributeKey::AttrToken, &token_info.token.clone());
        encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, token_info.atl as i32);

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

    fn store_token(&self) -> Result<(), ErrorCode> {
        for token_info in &self.token_infos {
            let companion_token = CompanionTokenInfo {
                template_id: self.obtain_param.template_id,
                device_type: token_info.device_type,
                token: token_info.token.clone(),
                atl: token_info.atl,
                added_time: TimeKeeperRegistry::get()
                    .get_rtc_time()
                    .map_err(|e| p!(e))?,
            };
            HostDbManagerRegistry::get_mut().add_token(&companion_token)?;
        }

        Ok(())
    }
}

impl HostRequest for HostDeviceObtainTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, _input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_e!("HostDeviceObtainTokenRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDeviceObtainTokenRequest prepare start");
        let HostRequestInput::ObtainTokenBegin(_ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        let sec_message = self.create_prepare_sec_message()?;

        Ok(HostRequestOutput::ObtainTokenBegin(
            HostProcessPreObtainTokenOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn end(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDeviceObtainTokenRequest prepare start");
        let HostRequestInput::ObtainTokenEnd(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;
        let sec_message = self.create_begin_sec_message()?;
        self.store_token()?;
        let max_atl = self
            .token_infos
            .iter()
            .map(|info| info.atl as i32)
            .max()
            .unwrap_or(AuthTrustLevel::Atl0 as i32);
        Ok(HostRequestOutput::ObtainTokenEnd(
            HostProcessObtainTokenOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
                atl: max_atl,
            },
        ))
    }
}
