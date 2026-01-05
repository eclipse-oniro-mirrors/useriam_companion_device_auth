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
use crate::jobs::message_crypto;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct DeviceTokenInfo {
    pub device_type: DeviceType,
    pub challenge: u64,
    pub atl: AuthTrustLevel,
    pub token: Vec<u8>,
}

pub fn generate_token(
    device_type: DeviceType,
    challenge: u64,
    atl: AuthTrustLevel,
) -> Result<DeviceTokenInfo, ErrorCode> {
    let mut token = [0u8; TOKEN_KEY_LEN];
    CryptoEngineRegistry::get().secure_random(&mut token).map_err(|_| {
        log_e!("secure_random fail");
        ErrorCode::GeneralError
    })?;

    let token_info = DeviceTokenInfo { device_type, challenge, atl, token: token.to_vec() };

    Ok(token_info)
}
