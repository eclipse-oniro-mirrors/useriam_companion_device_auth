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
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::{HostBinding, HostBindingSk};
use crate::traits::host_binding_db_manager::HostBindingDbManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::{log_e, p, Vec};
use crate::traits::log_trace::RustFileId;
pub(crate) const FILE_ID: u16 = RustFileId::HostBindingDbHelper as u16;
pub fn add_host_binding(device_info: &HostBinding, sk_info: &HostBindingSk) -> Result<Option<i32>, ErrorCode> {
    let mut same_device_replaced_binding_id = None;
    if let Ok(info) = HostBindingDbManagerRegistry::get()
        .get_device_by_device_key(device_info.user_info.user_id, &device_info.device_key)
    {
        if HostBindingDbManagerRegistry::get_mut().remove_device(info.binding_id).is_ok() {
            same_device_replaced_binding_id = Some(info.binding_id);
        } else {
            log_e!("remove device fail");
        }
    }

    let cross_device_replaced_binding_id = HostBindingDbManagerRegistry::get_mut().add_device(device_info, sk_info)?;
    if same_device_replaced_binding_id.is_some() && cross_device_replaced_binding_id.is_some() {
        log_e!(
            "unexpected: both same-device replacement ({:?}) and cross-device eviction ({:?}) occurred",
            same_device_replaced_binding_id,
            cross_device_replaced_binding_id
        );
    }
    Ok(same_device_replaced_binding_id.or(cross_device_replaced_binding_id))
}

pub fn update_host_binding_last_used_time(binding_id: i32) -> Result<(), ErrorCode> {
    let mut device_info = HostBindingDbManagerRegistry::get_mut().get_device_by_binding_id(binding_id)?;
    device_info.last_used_time = TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?;
    HostBindingDbManagerRegistry::get_mut().update_device(&device_info)?;
    Ok(())
}

pub fn get_session_key(binding_id: i32, salt: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    let sk = HostBindingDbManagerRegistry::get_mut().read_device_sk(binding_id).map_err(|e| p!(e))?;
    CryptoEngineRegistry::get().hkdf(salt, &sk.sk).map_err(|e| p!(e))
}
