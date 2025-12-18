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
    CompanionBeginAddHostBindingInputFfi, CompanionBeginAddHostBindingOutputFfi,
    CompanionEndAddHostBindingInputFfi, CompanionEndAddHostBindingOutputFfi,
    CompanionInitKeyNegotiationInputFfi, CompanionInitKeyNegotiationOutputFfi,
    CompanionProcessCheckInputFfi, DataArray1024Ffi, DeviceKeyFfi, PersistedHostBindingStatusFfi,
};
use crate::impls::default_companion_db_manager::CURRENT_VERSION;
use crate::jobs::companion_db_helper;
use crate::jobs::message_crypto;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::companion_request_manager::{
    CompanionRequest, CompanionRequestInput, CompanionRequestManagerRegistry,
    CompanionRequestOutput,
};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::crypto_engine::KeyPair;
use crate::traits::db_manager::{DeviceKey, HostDeviceInfo, HostDeviceSk, UserInfo};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyNegoParam {
    pub request_id: i32,
    pub companion_device_key: DeviceKey,
    pub host_device_key: DeviceKey,
    pub algorithm_list: Vec<u16>,
    pub challenge: u64,
    pub key_pair: Option<KeyPair>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct BindingParam {
    pub public_key: Vec<u8>,
    pub salt: [u8; HKDF_SALT_SIZE],
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct CompanionDeviceEnrollRequest {
    pub key_nego_param: KeyNegoParam,
    pub binding_param: BindingParam,
    pub session_key: Vec<u8>,
    pub sk: Vec<u8>,
    pub binding_id: i32,
}

impl CompanionDeviceEnrollRequest {
    pub fn new(input: &CompanionInitKeyNegotiationInputFfi) -> Result<Self, ErrorCode> {
        let host_device_key = DeviceKey::try_from(&input.host_device_key)?;
        let companion_device_key = DeviceKey::try_from(&input.companion_device_key)?;

        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get()
            .secure_random(&mut challenge)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;
        Ok(Self {
            key_nego_param: KeyNegoParam {
                request_id: input.request_id,
                companion_device_key: companion_device_key,
                host_device_key: host_device_key,
                algorithm_list: Vec::from([AlgoType::X25519 as u16]),
                challenge: u64::from_ne_bytes(challenge),
                key_pair: None,
            },
            binding_param: BindingParam {
                public_key: Vec::new(),
                salt: [0u8; HKDF_SALT_SIZE],
            },
            session_key: Vec::new(),
            sk: Vec::new(),
            binding_id: 0,
        })
    }

    fn get_request_id(&self) -> i32 {
        self.key_nego_param.request_id
    }

    fn get_challenge(&self) -> u64 {
        self.key_nego_param.challenge
    }

    fn get_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        match &self.key_nego_param.key_pair {
            Some(k) => Ok(k.clone()),
            None => {
                log_e!("x25519 key pair not set");
                Err(ErrorCode::GeneralError)
            }
        }
    }

    fn parse_key_nego_request_data(&mut self, sec_data: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_data).map_err(|e| p!(e))?;
        let algorithm_list = attribute
            .get_u16_vec(AttributeKey::AttrAlgoList)
            .map_err(|e| p!(e))?;

        if !algorithm_list.contains(&(AlgoType::X25519 as u16)) {
            return Err(ErrorCode::GeneralError);
        }
        Ok(())
    }

    fn parse_key_nego_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Ok(()) = self.parse_key_nego_request_data(value) {
                return Ok(());
            }
        }

        log_e!("No valid key_nego message found in sec_message");
        Err(ErrorCode::GeneralError)
    }

    fn create_key_nego_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let key_pair = CryptoEngineRegistry::get()
            .generate_x25519_key_pair()
            .map_err(|e| p!(e))?;
        self.key_nego_param.key_pair = Some(key_pair.clone());

        let mut attribute = Attribute::new();
        attribute.set_u16(AttributeKey::AttrAlgoList, AlgoType::X25519 as u16);
        attribute.set_u64(AttributeKey::AttrChallenge, self.key_nego_param.challenge);
        attribute.set_u8_slice(AttributeKey::AttrPublicKey, &key_pair.pub_key);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());

        Ok(final_attribute.to_bytes()?)
    }

    fn init_device_info(&mut self) -> Result<(HostDeviceInfo, HostDeviceSk), ErrorCode> {
        let binding_id = CompanionDbManagerRegistry::get()
            .generate_unique_binding_id()
            .map_err(|e| p!(e))?;
        let device_info = HostDeviceInfo {
            binding_id,
            device_key: self.key_nego_param.host_device_key.clone(),
            user_info: UserInfo {
                user_id: self.key_nego_param.companion_device_key.user_id,
                user_type: 0,
            },
            binding_time: TimeKeeperRegistry::get()
                .get_rtc_time()
                .map_err(|e| p!(e))?,
            last_used_time: 0,
            is_token_valid: false,
        };

        let sk_info = HostDeviceSk {
            sk: self.sk.clone(),
        };

        Ok((device_info, sk_info))
    }

    fn parse_enroll_request_data(&mut self, message_data: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let device_id = attribute
            .get_string(AttributeKey::AttrDeviceId)
            .map_err(|e| p!(e))?;
        let user_id = attribute
            .get_i32(AttributeKey::AttrUserId)
            .map_err(|e| p!(e))?;
        let public_key = attribute
            .get_u8_slice(AttributeKey::AttrPublicKey)
            .map_err(|e| p!(e))?;
        let salt = attribute
            .get_u8_slice(AttributeKey::AttrSalt)
            .map_err(|e| p!(e))?;
        let tag = attribute
            .get_u8_slice(AttributeKey::AttrTag)
            .map_err(|e| p!(e))?;
        let iv = attribute
            .get_u8_slice(AttributeKey::AttrIv)
            .map_err(|e| p!(e))?;
        let encrypt_data = attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        let key_pair = self.get_key_pair()?;
        let sk = CryptoEngineRegistry::get()
            .x25519_ecdh(&key_pair, public_key)
            .map_err(|e| {
                log_e!("x25519 computation failed for {:?}", e);
                ErrorCode::GeneralError
            })?;

        let session_key = CryptoEngineRegistry::get()
            .hkdf(&salt, &sk)
            .map_err(|e| p!(e))?;
        let decrypt_data = message_crypto::decrypt_sec_message(encrypt_data, &session_key, tag, iv)
            .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let decrypt_device_id = decrypt_attribute
            .get_string(AttributeKey::AttrDeviceId)
            .map_err(|e| p!(e))?;
        let decrypt_user_id = decrypt_attribute
            .get_i32(AttributeKey::AttrUserId)
            .map_err(|e| p!(e))?;
        let challenge = decrypt_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;

        if device_id != decrypt_device_id {
            log_e!(
                "device_id check fail, expected: {}, got: {}",
                device_id,
                decrypt_device_id
            );
            return Err(ErrorCode::GeneralError);
        }

        if user_id != decrypt_user_id {
            log_e!(
                "user_id check fail, expected: {}, got: {}",
                user_id,
                decrypt_user_id
            );
            return Err(ErrorCode::GeneralError);
        }

        if self.get_challenge() != challenge {
            log_e!(
                "challenge check fail, expected: {}, got: {}",
                self.get_challenge(),
                challenge
            );
            return Err(ErrorCode::GeneralError);
        }

        self.binding_param.salt.copy_from_slice(salt);
        self.session_key = session_key;
        self.sk = sk;
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Ok(()) = self.parse_enroll_request_data(value) {
                return Ok(());
            }
        }
        log_e!("No valid binding message found in sec_message");
        Err(ErrorCode::GeneralError)
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_string(
            AttributeKey::AttrDeviceId,
            self.key_nego_param.companion_device_key.device_id.clone(),
        );
        encrypt_attribute.set_i32(
            AttributeKey::AttrUserId,
            self.key_nego_param.companion_device_key.user_id,
        );
        let (encrypt_data, tag, iv) = message_crypto::encrypt_sec_message(
            encrypt_attribute.to_bytes()?.as_slice(),
            &self.session_key,
        )
        .map_err(|e| p!(e))?;

        let mut attribute = Attribute::new();
        attribute.set_string(
            AttributeKey::AttrDeviceId,
            self.key_nego_param.companion_device_key.device_id.clone(),
        );
        attribute.set_i32(
            AttributeKey::AttrUserId,
            self.key_nego_param.companion_device_key.user_id,
        );
        attribute.set_i32(AttributeKey::AttrEsl, ExecutorSecurityLevel::Esl2 as i32);
        attribute.set_i32(AttributeKey::AttrTrackAbilityLevel, 0);
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.binding_param.salt);
        attribute.set_u8_slice(AttributeKey::AttrTag, &tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        Ok(final_attribute.to_bytes()?)
    }

    fn store_device_info(&mut self) -> Result<i32, ErrorCode> {
        let (device_info, sk_info) = self.init_device_info()?;
        companion_db_helper::add_host_device(&device_info, &sk_info)?;
        Ok(device_info.binding_id)
    }
}

impl CompanionRequest for CompanionDeviceEnrollRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(
        &mut self,
        input: CompanionRequestInput,
    ) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceEnrollRequest prepare start");
        let CompanionRequestInput::KeyNego(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_key_nego_sec_message(ffi_input.sec_message.as_slice())?;
        let sec_message = self.create_key_nego_sec_message()?;
        Ok(CompanionRequestOutput::KeyNego(
            CompanionInitKeyNegotiationOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn begin(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceEnrollRequest begin start");
        let CompanionRequestInput::EnrollBegin(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;

        let sec_message = self.create_begin_sec_message()?;
        let binding_id = self.store_device_info()?;
        let device_info = companion_db_helper::get_host_device(binding_id)?;
        self.binding_id = binding_id;
        Ok(CompanionRequestOutput::EnrollBegin(
            CompanionBeginAddHostBindingOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
                binding_id: binding_id,
                binding_status: PersistedHostBindingStatusFfi {
                    binding_id: binding_id,
                    companion_user_id: device_info.user_info.user_id,
                    host_device_key: DeviceKeyFfi::try_from(device_info.device_key)?,
                    is_token_valid: device_info.is_token_valid,
                },
            },
        ))
    }

    fn end(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceEnrollRequest end start");
        let CompanionRequestInput::EnrollEnd(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        if ffi_input.result != 0 {
            return Err(ErrorCode::GeneralError);
        }
        companion_db_helper::update_host_device_last_used_time(self.binding_id)?;
        Ok(CompanionRequestOutput::EnrollEnd(
            CompanionEndAddHostBindingOutputFfi {
                binding_id: self.binding_id,
            },
        ))
    }
}
