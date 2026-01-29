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
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::CompanionTokenInfo;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::{log_e, p, Vec};

#[derive(Debug, Clone, PartialEq)]
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

pub fn add_companion_device_token(template_id: u64, token_infos: &Vec<DeviceTokenInfo>) -> Result<(), ErrorCode> {
    for token_info in token_infos {
        let companion_token = CompanionTokenInfo {
            template_id,
            device_type: token_info.device_type,
            token: token_info.token.clone().try_into().map_err(|e| {
                log_e!("try_into fail: {:?}", e);
                ErrorCode::GeneralError
            })?,
            atl: token_info.atl,
            added_time: TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?,
        };
        HostDbManagerRegistry::get_mut().add_token(&companion_token)?;
    }

    Ok(())
}
