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

use crate::jobs::message_crypto;

use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, p, Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct SecCommonRequest {
    pub salt: [u8; HKDF_SALT_SIZE],
    pub tag: [u8; AES_GCM_TAG_SIZE],
    pub iv: [u8; AES_GCM_IV_SIZE],
    pub encrypt_data: Vec<u8>,
}

impl SecCommonRequest {
    pub fn decode(message: &[u8], _device_type: DeviceType) -> Result<Self, ErrorCode> {
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(AttributeKey::AttrMessage).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let salt_slice = message_attribute.get_u8_slice(AttributeKey::AttrSalt).map_err(|e| p!(e))?;
        let tag_slice = message_attribute.get_u8_slice(AttributeKey::AttrTag).map_err(|e| p!(e))?;
        let iv_slice = message_attribute.get_u8_slice(AttributeKey::AttrIv).map_err(|e| p!(e))?;
        let encrypt_data_slice = message_attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        let salt: [u8; HKDF_SALT_SIZE] = salt_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;
        let tag: [u8; AES_GCM_TAG_SIZE] = tag_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;
        let iv: [u8; AES_GCM_IV_SIZE] = iv_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;
        let encrypt_data = encrypt_data_slice.to_vec();

        Ok(Self { salt, tag, iv, encrypt_data })
    }

    pub fn encode(&self, _device_type: DeviceType) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);
        attribute.set_u8_slice(AttributeKey::AttrTag, &self.tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &self.iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &self.encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        final_attribute.to_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecCommonReply {
    pub tag: [u8; AES_GCM_TAG_SIZE],
    pub iv: [u8; AES_GCM_IV_SIZE],
    pub encrypt_data: Vec<u8>,
}

impl SecCommonReply {
    pub fn decode(message: &[u8], _device_type: DeviceType) -> Result<Self, ErrorCode> {
        let attribute = Attribute::try_from_bytes(message).map_err(|e| p!(e))?;
        let message_data = attribute.get_u8_slice(AttributeKey::AttrMessage).map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let tag_slice = message_attribute.get_u8_slice(AttributeKey::AttrTag).map_err(|e| p!(e))?;
        let iv_slice = message_attribute.get_u8_slice(AttributeKey::AttrIv).map_err(|e| p!(e))?;
        let encrypt_data_slice = message_attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        let tag: [u8; AES_GCM_TAG_SIZE] = tag_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;
        let iv: [u8; AES_GCM_IV_SIZE] = iv_slice.try_into().map_err(|_| ErrorCode::GeneralError)?;
        let encrypt_data = encrypt_data_slice.to_vec();

        Ok(Self { tag, iv, encrypt_data })
    }

    pub fn encode(&self, _device_type: DeviceType) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrTag, &self.tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &self.iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &self.encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        final_attribute.to_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecIssueToken {
    pub challenge: u64,
    pub atl: i32,
    pub token: Vec<u8>,
}

impl SecIssueToken {
    pub fn decrypt_issue_token(
        sec_message: &[u8],
        device_type: DeviceType,
        session_key: &[u8],
    ) -> Result<Self, ErrorCode> {
        let output = SecCommonRequest::decode(sec_message, device_type)?;

        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;

        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrChallenge).map_err(|e| p!(e))?;
        let token = decrypt_attribute.get_u8_slice(AttributeKey::AttrToken).map_err(|e| p!(e))?;
        let atl = decrypt_attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;

        Ok(Self { challenge, atl, token: token.to_vec() })
    }

    pub fn encrypt_issue_token(
        &self,
        salt: &[u8],
        device_type: DeviceType,
        session_key: &[u8],
    ) -> Result<Vec<u8>, ErrorCode> {
        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);
        encrypt_attribute.set_u8_slice(AttributeKey::AttrToken, &self.token.clone());
        encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, self.atl);

        let (encrypt_data, tag, iv) =
            message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), session_key)
                .map_err(|e| p!(e))?;

        let issue_token_request =
            SecCommonRequest { salt: salt.try_into().map_err(|_| ErrorCode::GeneralError)?, tag, iv, encrypt_data };
        let output = issue_token_request.encode(device_type)?;
        Ok(output)
    }
}
