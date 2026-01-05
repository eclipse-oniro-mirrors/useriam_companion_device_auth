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
use crate::traits::companion_db_manager::{CompanionDbManagerRegistry, HostDeviceFilter};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::{HostDeviceInfo, HostDeviceSk};
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::{log_e, log_i, p, Box, Vec};

pub fn add_host_device(device_info: &HostDeviceInfo, sk_info: &HostDeviceSk) -> Result<(), ErrorCode> {
    if let Ok(info) = CompanionDbManagerRegistry::get()
        .get_device_by_device_key(device_info.user_info.user_id, &device_info.device_key)
    {
        let _ = CompanionDbManagerRegistry::get_mut().remove_device(info.binding_id);
    }

    CompanionDbManagerRegistry::get_mut().add_device(device_info, sk_info)
}

pub fn update_host_device_last_used_time(binding_id: i32) -> Result<(), ErrorCode> {
    let mut device_info = CompanionDbManagerRegistry::get_mut().get_device_by_binding_id(binding_id)?;
    device_info.last_used_time = TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?;
    CompanionDbManagerRegistry::get_mut().update_device(&device_info)?;
    Ok(())
}

pub fn get_session_key(binding_id: i32, salt: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    let sk = CompanionDbManagerRegistry::get_mut()
        .read_device_sk(binding_id)
        .map_err(|e| p!(e))?;
    Ok(CryptoEngineRegistry::get().hkdf(&salt, &sk.sk).map_err(|e| p!(e))?)
}
