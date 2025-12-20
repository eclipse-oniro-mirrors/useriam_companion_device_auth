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

use crate::common::constants::ErrorCode;
use crate::common::types::Udid;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::utils::attribute::{Attribute, AttributeKey};
use crate::Vec;
use crate::{log_e, p};

#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub enum MessageSignParam {
    NoSign,
    Executor(KeyPair),
    Framework(Vec<u8>),
}

#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageCodec {
    sign_param: MessageSignParam,
}

impl MessageCodec {
    pub fn new(sign_param: MessageSignParam) -> Self {
        Self { sign_param }
    }

    pub fn serialize_attribute(&self, attr: &Attribute) -> Result<Vec<u8>, ErrorCode> {
        let data_attr_bytes = attr.to_bytes().map_err(|e| p!(e))?;
        let mut data_and_sign_attr = Attribute::new();
        data_and_sign_attr.set_u8_slice(AttributeKey::AttrData, &data_attr_bytes);

        match &self.sign_param {
            MessageSignParam::NoSign => {}
            MessageSignParam::Executor(key_pair) => {
                let signature_bytes = CryptoEngineRegistry::get()
                    .ed25519_sign(&key_pair.pri_key, &data_attr_bytes)
                    .map_err(|e| p!(e))?;
                data_and_sign_attr.set_u8_slice(AttributeKey::AttrSignature, &signature_bytes);
            }
            MessageSignParam::Framework(_) => {
                log_e!("executor sign is not supported");
                return Err(ErrorCode::GeneralError);
            }
        }

        let data_and_sign_attr_bytes = data_and_sign_attr.to_bytes().map_err(|e| p!(e))?;
        let mut root_attr = Attribute::new();
        root_attr.set_u8_slice(AttributeKey::AttrRoot, &data_and_sign_attr_bytes);
        root_attr.to_bytes()
    }

    pub fn deserialize_attribute(&self, bytes: &[u8]) -> Result<Attribute, ErrorCode> {
        let root_attr = Attribute::try_from_bytes(bytes).map_err(|e| p!(e))?;
        let root_attr_bytes = root_attr
            .get_u8_slice(AttributeKey::AttrRoot)
            .map_err(|e| p!(e))?;
        let data_and_sign_attr = Attribute::try_from_bytes(root_attr_bytes).map_err(|e| p!(e))?;

        let data_bytes = data_and_sign_attr
            .get_u8_slice(AttributeKey::AttrData)
            .map_err(|e| p!(e))?;
        match &self.sign_param {
            MessageSignParam::NoSign => {}
            MessageSignParam::Executor(key_pair) => {
                let signature_bytes = data_and_sign_attr
                    .get_u8_slice(AttributeKey::AttrSignature)
                    .map_err(|e| p!(e))?;
                CryptoEngineRegistry::get()
                    .ed25519_verify(&key_pair.pub_key, data_bytes, signature_bytes)
                    .map_err(|e| p!(e))?;
            }
            MessageSignParam::Framework(pub_key) => {
                let signature_bytes = data_and_sign_attr
                    .get_u8_slice(AttributeKey::AttrSignature)
                    .map_err(|e| p!(e))?;
                CryptoEngineRegistry::get()
                    .ed25519_verify(&pub_key, data_bytes, signature_bytes)
                    .map_err(|e| p!(e))?;
            }
        }

        Attribute::try_from_bytes(data_bytes)
    }
}
