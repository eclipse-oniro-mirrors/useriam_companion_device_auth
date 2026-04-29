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

use crate::common::constants::{Capability, ErrorCode, ProcessorType};
use crate::traits::companion_device_db_manager::CompanionDeviceDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::CompanionDevice;
use crate::{log_e, log_i, p, Box, String, Vec};
use crate::traits::log_trace::RustFileId;
pub(crate) const FILE_ID: u16 = RustFileId::COMPANION_DEVICE_DB_HELPER as u16;
pub fn check_device_capability(template_id: u64, required_capability: Capability) -> Result<(), ErrorCode> {
    let device_info = CompanionDeviceDbManagerRegistry::get().get_device(template_id).map_err(|e| {
        log_e!("get_device failed for template_id:{:04x}, err:{:?}", template_id as u16, e);
        e
    })?;

    let capability_value = required_capability as u16;
    if !device_info.capability_list.contains(&capability_value) {
        log_e!(
            "Device does not have required capability, template_id:{:04x}, required:{:?}",
            template_id as u16,
            required_capability
        );
        return Err(ErrorCode::GeneralError);
    }

    log_i!(
        "Device capability check passed, template_id:{:04x}, capability:{:?}",
        template_id as u16,
        required_capability
    );
    Ok(())
}

pub fn update_companion_device_valid_flag(template_id: u64, is_valid: bool) -> Result<(), ErrorCode> {
    let mut device_info = CompanionDeviceDbManagerRegistry::get_mut().get_device(template_id)?;
    device_info.is_valid = is_valid;
    CompanionDeviceDbManagerRegistry::get_mut().update_device(&device_info)?;
    Ok(())
}

pub fn get_companion_device_by_user_id(user_id: i32) -> Result<Vec<CompanionDevice>, ErrorCode> {
    let filter = Box::new(move |device_info: &CompanionDevice| device_info.user_info.user_id == user_id);
    let device_info = CompanionDeviceDbManagerRegistry::get_mut().get_device_list(filter);
    Ok(device_info)
}

pub fn delete_companion_device_token(template_id: u64) -> Result<(), ErrorCode> {
    CompanionDeviceDbManagerRegistry::get_mut().remove_token(template_id, ProcessorType::default())?;
    Ok(())
}

pub fn update_companion_device_info(
    template_id: u64,
    device_model_info: String,
    device_name: String,
    device_user_name: String,
) -> Result<(), ErrorCode> {
    let mut device_profile = CompanionDeviceDbManagerRegistry::get_mut().read_device_profile(template_id)?;
    device_profile.device_model_info = device_model_info;
    device_profile.device_name = device_name;
    device_profile.device_user_name = device_user_name;
    CompanionDeviceDbManagerRegistry::get_mut().write_device_profile(template_id, &device_profile)?;
    Ok(())
}

pub fn update_device_business_id(template_id: u64, business_ids: Vec<i32>) -> Result<(), ErrorCode> {
    let _device_info = CompanionDeviceDbManagerRegistry::get().get_device(template_id).map_err(|e| {
        log_e!("get_device failed for template_id:{:04x}, err:{:?}", template_id as u16, e);
        e
    })?;

    let mut device_profile = CompanionDeviceDbManagerRegistry::get_mut().read_device_profile(template_id)?;
    device_profile.business_ids = business_ids;
    CompanionDeviceDbManagerRegistry::get_mut().write_device_profile(template_id, &device_profile)
}

pub fn get_session_key(template_id: u64, processor_type: ProcessorType, salt: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    let sk_infos = CompanionDeviceDbManagerRegistry::get_mut().read_device_sk(template_id).map_err(|e| p!(e))?;
    for sk_info in sk_infos {
        if sk_info.processor_type == processor_type {
            return CryptoEngineRegistry::get().hkdf(salt, &sk_info.sk).map_err(|e| p!(e));
        }
    }
    log_e!("get_session_key fail");
    Err(ErrorCode::GeneralError)
}

pub fn verify_template(template_ids: Vec<u64>) -> Result<(), ErrorCode> {
    log_i!("verify_template start");
    let device_info_list = CompanionDeviceDbManagerRegistry::get().get_device_list(Box::new(|_| true));
    for device_info in device_info_list {
        if !template_ids.contains(&device_info.template_id) {
            if let Err(err) = CompanionDeviceDbManagerRegistry::get_mut().remove_device(device_info.template_id) {
                log_e!("remove_device failed, err: {:?}", err);
            }
        }
    }
    Ok(())
}
