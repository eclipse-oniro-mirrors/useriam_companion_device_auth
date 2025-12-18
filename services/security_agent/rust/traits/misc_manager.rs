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
use crate::log_e;
use crate::singleton_registry;
use crate::traits::crypto_engine::KeyPair;
use crate::Vec;
#[cfg(any(test, feature = "test-utils"))]
use mockall::automock;

#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait MiscManager {
    fn get_distribute_key(
        &self,
        local_udid: Udid,
        peer_udid: Udid,
    ) -> Result<crate::Vec<u8>, ErrorCode>;
    fn set_local_key_pair(&mut self, key_pair: KeyPair) -> Result<(), ErrorCode>;
    fn get_local_key_pair(&self) -> Result<KeyPair, ErrorCode>;
    fn set_fwk_pub_key(&mut self, pub_key: Vec<u8>) -> Result<(), ErrorCode>;
    fn get_fwk_pub_key(&self) -> Result<Vec<u8>, ErrorCode>;
}

pub struct DummyMiscManager;

impl MiscManager for DummyMiscManager {
    fn get_distribute_key(
        &self,
        _local_udid: Udid,
        _peer_udid: Udid,
    ) -> Result<crate::Vec<u8>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn set_local_key_pair(&mut self, _key_pair: KeyPair) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn get_local_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn set_fwk_pub_key(&mut self, _pub_key: Vec<u8>) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn get_fwk_pub_key(&self) -> Result<Vec<u8>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(MiscManagerRegistry, MiscManager, DummyMiscManager);
