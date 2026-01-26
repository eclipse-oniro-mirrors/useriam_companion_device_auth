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
use crate::common::types::Udid;
use crate::log_e;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair};
use crate::traits::misc_manager::MiscManager;
use crate::Vec;
use core::mem::size_of;

pub struct DefaultMiscManager {
    #[allow(dead_code)]
    udid: Option<Udid>,
    key_pair: Option<KeyPair>,
    fwk_pub_key: Option<Vec<u8>>,
}

impl DefaultMiscManager {
    pub fn new() -> Self {
        DefaultMiscManager { udid: None, key_pair: None, fwk_pub_key: None }
    }
}

impl MiscManager for DefaultMiscManager {
    fn get_distribute_key(&self, local_udid: Udid, peer_udid: Udid) -> Result<crate::Vec<u8>, ErrorCode> {
        const DUMMY_DISTRIBUTE_DEVICE_KEY: &[u8; 32] = b"DEVICE_AUTH_DISTRIBUT_DEVICE_KEY";

        let mut salt = Vec::with_capacity(size_of::<Udid>() * 2);
        if local_udid > peer_udid {
            salt.extend_from_slice(&local_udid.0);
            salt.extend_from_slice(&peer_udid.0);
        } else {
            salt.extend_from_slice(&peer_udid.0);
            salt.extend_from_slice(&local_udid.0);
        }

        let mut origin_key_data = Vec::with_capacity(DUMMY_DISTRIBUTE_DEVICE_KEY.len() + salt.len());
        origin_key_data.extend_from_slice(DUMMY_DISTRIBUTE_DEVICE_KEY);
        origin_key_data.extend_from_slice(&salt);
        CryptoEngineRegistry::get().sha256(&origin_key_data)
    }

    fn set_local_key_pair(&mut self, key_pair: KeyPair) -> Result<(), ErrorCode> {
        self.key_pair = Some(key_pair);
        Ok(())
    }

    fn get_local_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        match &self.key_pair {
            Some(k) => Ok(k.clone()),
            None => {
                log_e!("key pair not set");
                Err(ErrorCode::GeneralError)
            },
        }
    }

    fn set_fwk_pub_key(&mut self, pub_key: Vec<u8>) -> Result<(), ErrorCode> {
        if pub_key.is_empty() {
            log_e!("framework public key is empty");
            return Err(ErrorCode::GeneralError);
        }

        self.fwk_pub_key = Some(pub_key);
        Ok(())
    }

    fn get_fwk_pub_key(&self) -> Result<Vec<u8>, ErrorCode> {
        self.fwk_pub_key.clone().ok_or_else(|| {
            log_e!("framework public key not set");
            ErrorCode::GeneralError
        })
    }
}

impl Default for DefaultMiscManager {
    fn default() -> Self {
        Self::new()
    }
}
