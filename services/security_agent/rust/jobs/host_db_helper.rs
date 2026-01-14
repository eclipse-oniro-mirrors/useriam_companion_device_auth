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
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::{
    CompanionDeviceBaseInfo, CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk,
};
use crate::traits::host_db_manager::{CompanionDeviceFilter, HostDbManagerRegistry};
use crate::String;
use crate::{log_e, log_i, p, Box, Vec};

pub fn update_companion_device_valid_flag(template_id: u64, is_valid: bool) -> Result<(), ErrorCode> {
    let mut device_info = HostDbManagerRegistry::get_mut().get_device(template_id)?;
    device_info.is_valid = is_valid;
    HostDbManagerRegistry::get_mut().update_device(&device_info)?;
    Ok(())
}

pub fn get_companion_device_by_user_id(user_id: i32) -> Result<Vec<CompanionDeviceInfo>, ErrorCode> {
    let filter = Box::new(move |device_info: &CompanionDeviceInfo| device_info.user_info.user_id == user_id);
    let device_info = HostDbManagerRegistry::get_mut().get_device_list(filter);
    Ok(device_info)
}

pub fn delete_companion_device_token(template_id: u64) -> Result<(), ErrorCode> {
    HostDbManagerRegistry::get_mut().remove_token(template_id, DeviceType::None)?;
    Ok(())
}

pub fn update_companion_device_info(
    template_id: u64,
    device_name: String,
    device_user_name: String,
) -> Result<(), ErrorCode> {
    let mut device_base_info = HostDbManagerRegistry::get_mut().read_device_base_info(template_id)?;
    device_base_info.device_name = device_name;
    device_base_info.device_user_name = device_user_name;
    HostDbManagerRegistry::get_mut().write_device_base_info(template_id, &device_base_info)?;
    Ok(())
}

pub fn update_device_business_id(template_id: u64, business_ids: Vec<i32>) -> Result<(), ErrorCode> {
    // Check if templateId exists (supports cross-user query)
    let _device_info = HostDbManagerRegistry::get().get_device(template_id).map_err(|e| {
        log_e!("get_device failed for template_id:{:x}, err:{:?}", template_id as u16, e);
        e
    })?;

    let mut device_base_info = HostDbManagerRegistry::get_mut().read_device_base_info(template_id)?;
    device_base_info.business_ids = business_ids;
    HostDbManagerRegistry::get_mut().write_device_base_info(template_id, &device_base_info)
}

pub fn get_session_key(template_id: u64, device_type: DeviceType, salt: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    let sk_infos = HostDbManagerRegistry::get_mut()
        .read_device_sk(template_id)
        .map_err(|e| p!(e))?;
    for sk_info in sk_infos {
        if sk_info.device_type == device_type {
            return Ok(CryptoEngineRegistry::get().hkdf(&salt, &sk_info.sk).map_err(|e| p!(e))?);
        }
    }
    log_e!("get_session_key fail");
    return Err(ErrorCode::GeneralError);
}

pub fn verify_template(template_ids: Vec<u64>) -> Result<(), ErrorCode> {
    log_i!("verify_template start");
    let device_info_list = HostDbManagerRegistry::get().get_device_list(Box::new(|_| true));
    for device_info in device_info_list {
        if !template_ids.contains(&device_info.template_id) {
            if let Err(err) = HostDbManagerRegistry::get_mut().remove_device(device_info.template_id) {
                log_e!("remove_device failed, err: {:?}", err);
            }
        }
    }
    Ok(())
}