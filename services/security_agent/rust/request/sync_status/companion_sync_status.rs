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
    CompanionProcessCheckInputFfi, CompanionProcessCheckOutputFfi, DataArray1024Ffi,
};
use crate::jobs::companion_db_helper;
use crate::jobs::message_crypto;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::companion_request_manager::{
    CompanionRequest, CompanionRequestInput, CompanionRequestOutput,
};
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngineRegistry};
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct CompanionDeviceSyncStatusRequest {
    pub binding_id: i32,
    pub challenge: u64,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub algorithm_list: Vec<u16>,
    pub capability_list: Vec<u16>,
}

impl CompanionDeviceSyncStatusRequest {
    pub fn new(input: &CompanionProcessCheckInputFfi) -> Result<Self, ErrorCode> {
        let algorithm_list = Vec::from([AlgoType::X25519 as u16]);

        Ok(CompanionDeviceSyncStatusRequest {
            binding_id: input.binding_id,
            challenge: input.challenge,
            salt: input.salt,
            algorithm_list,
            capability_list: input.capability_list.try_into().map_err(|e| p!(e))?,
        })
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);
        encrypt_attribute.set_u16_slice(AttributeKey::AttrAlgoList, &self.algorithm_list);
        encrypt_attribute.set_u16_slice(AttributeKey::AttrCapabilityList, &self.capability_list);

        let attribute_bytes = encrypt_attribute.to_bytes()?;

        let session_key = companion_db_helper::get_session_key(self.binding_id, &self.salt)?;
        let (encrypt_data, tag, iv) =
            message_crypto::encrypt_sec_message(&attribute_bytes, &session_key)
                .map_err(|e| p!(e))?;

        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrTag, &tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        Ok(final_attribute.to_bytes()?)
    }
}

impl CompanionRequest for CompanionDeviceSyncStatusRequest {
    fn get_request_id(&self) -> i32 {
        self.binding_id
    }

    fn prepare(
        &mut self,
        _input: CompanionRequestInput,
    ) -> Result<CompanionRequestOutput, ErrorCode> {
        log_e!("CompanionDeviceSyncStatusRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceSyncStatusRequest begin start");
        let CompanionRequestInput::SyncStatus(_ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        let reply_sec_message = self.create_begin_sec_message()?;

        Ok(CompanionRequestOutput::SyncStatus(
            CompanionProcessCheckOutputFfi {
                sec_message: DataArray1024Ffi::try_from(reply_sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn end(&mut self, _input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}
