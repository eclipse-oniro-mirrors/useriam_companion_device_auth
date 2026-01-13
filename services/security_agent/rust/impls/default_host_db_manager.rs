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
use crate::jobs::host_db_helper;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::{
    CompanionDeviceBaseInfo, CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk, CompanionTokenInfo,
    DeviceKey, UserInfo,
};
use crate::traits::host_db_manager::{CompanionDeviceFilter, HostDbManager};
use crate::traits::storage_io::StorageIoRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::parcel::Parcel;
use crate::vec;
use crate::String;
use crate::{log_e, log_i, p, singleton_registry, Box, Vec};
#[cfg(not(any(test, feature = "test-utils")))]
use alloc::format;
use core::mem;
#[cfg(any(test, feature = "test-utils"))]
use std::format;

pub const CURRENT_VERSION: i32 = 0;
pub const HOST_DEVICE_DB: &str = "companion_device_db";
pub const HOST_DEVICE_BASE_INFO: &str = "companion_device_base_info";
pub const HOST_DEVICE_CAPABILTY_INFO: &str = "companion_device_capability_info";
pub const HOST_DEVICE_SK: &str = "companion_device_sk";

const MAX_DEVICE_NUM: usize = 1;
const MAX_TOKEN_NUM: usize = 1;

pub struct DefaultHostDbManager {
    pub companion_device_infos: Vec<CompanionDeviceInfo>,
    pub companion_token_infos: Vec<CompanionTokenInfo>,
}

impl DefaultHostDbManager {
    pub fn new() -> Self {
        DefaultHostDbManager {
            companion_device_infos: Vec::with_capacity(MAX_DEVICE_NUM),
            companion_token_infos: Vec::with_capacity(MAX_TOKEN_NUM),
        }
    }

    fn get_device_index_by_template_id(&self, template_id: u64) -> Option<usize> {
        self.companion_device_infos
            .iter()
            .position(|device_info| template_id == device_info.template_id)
    }

    fn find_device_index_by_filter(&self, filter: &CompanionDeviceFilter) -> Option<usize> {
        self.companion_device_infos.iter().position(|device| filter(device))
    }

    fn get_token_index_by_template_info(&self, template_id: u64, device_type: DeviceType) -> Option<usize> {
        self.companion_token_infos
            .iter()
            .position(|token| token.template_id == template_id && token.device_type == device_type)
    }

    fn generate_unique_id<'a, T, F, G>(&'a self, collection: F, id_extractor: G) -> Result<u64, ErrorCode>
    where
        T: 'a,
        F: Fn() -> &'a [T] + 'a,
        G: Fn(&T) -> u64 + 'a,
    {
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 100;
        loop {
            let mut random_bytes = [0u8; 8];
            CryptoEngineRegistry::get().secure_random(&mut random_bytes).map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;
            let random = u64::from_ne_bytes(random_bytes);

            let exists = collection().iter().any(|item| id_extractor(item) == random);
            if !exists {
                return Ok(random);
            }

            attempts += 1;
            if attempts >= MAX_ATTEMPTS {
                log_e!("random generate error");
                return Err(ErrorCode::GeneralError);
            }
        }
    }

    fn serialize_device_db(&self, parcel: &mut Parcel) -> Result<(), ErrorCode> {
        parcel.write_i32(CURRENT_VERSION);
        parcel.write_i32(self.companion_device_infos.len() as i32);

        for companion_device_info in &self.companion_device_infos {
            parcel.write_u64(companion_device_info.template_id);
            parcel.write_string(&companion_device_info.device_key.device_id);
            parcel.write_i32(companion_device_info.device_key.device_id_type);
            parcel.write_i32(companion_device_info.device_key.user_id);
            parcel.write_i32(companion_device_info.user_info.user_id);
            parcel.write_i32(companion_device_info.user_info.user_type);
            parcel.write_u64(companion_device_info.added_time);
            parcel.write_u16(companion_device_info.secure_protocol_id);
            parcel.write_u32(companion_device_info.is_valid as u32);
        }

        Ok(())
    }

    fn deserialize_device_db(&mut self, parcel: &mut Parcel) -> Result<(), ErrorCode> {
        let _version = parcel.read_i32().map_err(|_| ErrorCode::ReadParcelError)?;

        self.companion_device_infos.clear();
        let count = parcel.read_i32().map_err(|e| p!(e))?;
        if count < 0 {
            return Err(ErrorCode::BadParam);
        }
        let count = count as usize;

        for _ in 0..count {
            let template_id = parcel.read_u64().map_err(|e| p!(e))?;
            let device_id = parcel.read_string().map_err(|e| p!(e))?;
            let device_id_type = parcel.read_i32().map_err(|e| p!(e))?;
            let user_id = parcel.read_i32().map_err(|e| p!(e))?;
            let user_info_user_id = parcel.read_i32().map_err(|e| p!(e))?;
            let user_info_user_type = parcel.read_i32().map_err(|e| p!(e))?;
            let added_time = parcel.read_u64().map_err(|e| p!(e))?;
            let secure_protocol_id = parcel.read_u16().map_err(|e| p!(e))?;
            let is_valid_u32 = parcel.read_u32().map_err(|e| p!(e))?;

            let companion_device_info = CompanionDeviceInfo {
                template_id,
                device_key: DeviceKey { device_id, device_id_type, user_id },
                user_info: UserInfo { user_id: user_info_user_id, user_type: user_info_user_type },
                added_time,
                secure_protocol_id,
                is_valid: is_valid_u32 != 0,
            };

            self.companion_device_infos.push(companion_device_info);
            log_i!("companion_device_infos: {:?}", self.companion_device_infos);
        }

        Ok(())
    }

    fn serialize_device_base_info(
        &self,
        base_info: &CompanionDeviceBaseInfo,
        parcel: &mut Parcel,
    ) -> Result<(), ErrorCode> {
        parcel.write_i32(CURRENT_VERSION);
        parcel.write_string(&base_info.device_model);
        parcel.write_string(&base_info.device_name);
        parcel.write_string(&base_info.device_user_name);
        parcel.write_i32(base_info.business_ids.len() as i32);
        for &business_id in &base_info.business_ids {
            parcel.write_i32(business_id);
        }

        Ok(())
    }

    fn deserialize_device_base_info(&self, parcel: &mut Parcel) -> Result<CompanionDeviceBaseInfo, ErrorCode> {
        let _version = parcel.read_i32().map_err(|e| p!(e))?;
        let device_model = parcel.read_string().map_err(|e| p!(e))?;
        let device_name = parcel.read_string().map_err(|e| p!(e))?;
        let device_user_name = parcel.read_string().map_err(|e| p!(e))?;
        let business_ids_len = parcel.read_i32().map_err(|e| p!(e))? as usize;
        let mut business_ids = Vec::with_capacity(business_ids_len);
        for _ in 0..business_ids_len {
            let business_id = parcel.read_i32().map_err(|e| p!(e))?;
            business_ids.push(business_id);
        }

        Ok(CompanionDeviceBaseInfo { device_model, device_name, device_user_name, business_ids })
    }

    fn serialize_device_capability_info(
        &self,
        capability_infos: &Vec<CompanionDeviceCapability>,
        parcel: &mut Parcel,
    ) -> Result<(), ErrorCode> {
        parcel.write_i32(CURRENT_VERSION);
        parcel.write_i32(capability_infos.len() as i32);
        for capability_info in capability_infos {
            parcel.write_i32(capability_info.device_type as i32);
            parcel.write_i32(capability_info.esl as i32);
            parcel.write_i32(capability_info.track_ability_level);
        }

        Ok(())
    }

    fn deserialize_device_capability_info(
        &self,
        parcel: &mut Parcel,
    ) -> Result<Vec<CompanionDeviceCapability>, ErrorCode> {
        let _version = parcel.read_i32().map_err(|e| p!(e))?;
        let count = parcel.read_i32().map_err(|e| p!(e))?;
        if count < 0 {
            return Err(ErrorCode::BadParam);
        }
        let count = count as usize;

        let mut capability_infos: Vec<CompanionDeviceCapability> = Vec::with_capacity(count);

        for _ in 0..count {
            let device_type_value = parcel.read_i32().map_err(|e| p!(e))?;
            let esl_value = parcel.read_i32().map_err(|e| p!(e))?;
            let track_ability_level = parcel.read_i32().map_err(|e| p!(e))?;
            let device_type = DeviceType::try_from(device_type_value).map_err(|e| p!(e))?;
            let esl = ExecutorSecurityLevel::try_from(esl_value).map_err(|e| p!(e))?;
            let capability_info = CompanionDeviceCapability { device_type, esl, track_ability_level };

            capability_infos.push(capability_info);
        }

        Ok(capability_infos)
    }

    fn serialize_device_sk(&self, sk_infos: &Vec<CompanionDeviceSk>, parcel: &mut Parcel) -> Result<(), ErrorCode> {
        parcel.write_i32(CURRENT_VERSION);
        parcel.write_i32(sk_infos.len() as i32);

        for sk_info in sk_infos {
            parcel.write_i32(sk_info.device_type as i32);
            parcel.write_i32(sk_info.sk.len() as i32);
            parcel.write_bytes(&sk_info.sk);
        }

        Ok(())
    }

    fn deserialize_device_sk(&self, parcel: &mut Parcel) -> Result<Vec<CompanionDeviceSk>, ErrorCode> {
        let _version = parcel.read_i32().map_err(|e| p!(e))?;
        let count = parcel.read_i32().map_err(|e| p!(e))?;
        if count < 0 {
            return Err(ErrorCode::BadParam);
        }
        let count = count as usize;

        let mut sk_infos: Vec<CompanionDeviceSk> = Vec::with_capacity(count);

        for _ in 0..count {
            let device_type_value = parcel.read_i32().map_err(|e| p!(e))?;
            let device_type = DeviceType::try_from(device_type_value).map_err(|e| p!(e))?;
            let sk_len = parcel.read_i32().map_err(|e| p!(e))? as usize;
            let mut sk = vec![0u8; sk_len];
            parcel.read_bytes(&mut sk).map_err(|e| p!(e))?;

            let sk_info = CompanionDeviceSk { device_type, sk };

            sk_infos.push(sk_info);
        }

        Ok(sk_infos)
    }

    fn write_device_db(&self) -> Result<(), ErrorCode> {
        log_i!("write_device_db start");
        let mut parcel = Parcel::new();
        self.serialize_device_db(&mut parcel)?;
        StorageIoRegistry::get()
            .write(HOST_DEVICE_DB, parcel.as_slice())
            .map_err(|e| p!(e))?;
        Ok(())
    }

    fn wirte_device_extra_file(
        &self,
        template_id: u64,
        base_info: &CompanionDeviceBaseInfo,
        capability_info: &Vec<CompanionDeviceCapability>,
        sk_info: &Vec<CompanionDeviceSk>,
    ) -> Result<(), ErrorCode> {
        self.write_device_base_info(template_id, base_info)?;
        self.write_device_capability_info(template_id, capability_info)?;
        self.write_device_sk(template_id, sk_info)
    }

    fn remove_device_extra_file(&self, template_id: u64) {
        let _ = self.delete_device_base_info(template_id);
        let _ = self.delete_device_capability_info(template_id);
        let _ = self.delete_device_sk(template_id);
    }
}

impl HostDbManager for DefaultHostDbManager {
    fn add_device(
        &mut self,
        device_info: &CompanionDeviceInfo,
        base_info: &CompanionDeviceBaseInfo,
        capability_info: &Vec<CompanionDeviceCapability>,
        sk_info: &Vec<CompanionDeviceSk>,
    ) -> Result<(), ErrorCode> {
        log_i!("add_device start");
        if device_info.device_key.device_id.is_empty() {
            log_e!("Invalid device ID");
            return Err(ErrorCode::BadParam);
        }

        if self.companion_device_infos.len() >= MAX_DEVICE_NUM {
            log_e!("device num is reached limit");
            return Err(ErrorCode::ExceedLimit);
        }

        if self.get_device_index_by_template_id(device_info.template_id).is_some() {
            log_i!("template id already exists");
            return Err(ErrorCode::BadParam);
        }

        if let Err(err) = self.wirte_device_extra_file(device_info.template_id, base_info, capability_info, sk_info) {
            log_e!("write device extra file fail:{:?}", err);
            self.remove_device_extra_file(device_info.template_id);
            return Err(err);
        }

        self.companion_device_infos.push(device_info.clone());
        let result = self.write_device_db();
        if result.is_ok() {
            log_i!("Device added successfully, template_id: {:x}", device_info.template_id as u16);
            return result;
        }
        log_e!("write_device_db fail");
        if let Some(index) = self
            .companion_device_infos
            .iter()
            .position(|d| d.template_id == device_info.template_id)
        {
            self.companion_device_infos.remove(index);
        }
        result
    }

    fn get_device(&self, template_id: u64) -> Result<CompanionDeviceInfo, ErrorCode> {
        log_i!("get_device start");
        self.get_device_index_by_template_id(template_id)
            .map(|index| self.companion_device_infos[index].clone())
            .ok_or_else(|| {
                log_e!("No device matching filter found");
                ErrorCode::NotFound
            })
    }

    fn get_device_list(&self, filter: CompanionDeviceFilter) -> Vec<CompanionDeviceInfo> {
        log_i!("get_device_list start");
        self.companion_device_infos
            .iter()
            .filter(|device_info| filter(device_info))
            .cloned()
            .collect()
    }

    fn remove_device(&mut self, template_id: u64) -> Result<CompanionDeviceInfo, ErrorCode> {
        log_i!("remove_device start");
        let device_info = self
            .get_device_index_by_template_id(template_id)
            .map(|index| {
                let device = self.companion_device_infos.remove(index);
                log_i!("Device removed successfully, template_id: {:x}", device.template_id as u16);
                device
            })
            .ok_or_else(|| {
                log_i!("No device matching filter found for removal");
                ErrorCode::NotFound
            })?;
        if let Err(err) = self.write_device_db() {
            log_e!("write_device_db_with_fail_rollback fail:{:?}", err);
            self.companion_device_infos.push(device_info);
            return Err(err);
        }
        self.remove_device_extra_file(device_info.template_id);
        self.companion_token_infos
            .retain(|token| token.template_id != device_info.template_id);
        Ok(device_info)
    }

    fn update_device(&mut self, device_info: &CompanionDeviceInfo) -> Result<(), ErrorCode> {
        log_i!("update_device start");
        let index = self.get_device_index_by_template_id(device_info.template_id).ok_or_else(|| {
            log_i!("No template id matching");
            ErrorCode::NotFound
        })?;

        let device_info_old = self.companion_device_infos[index].clone();
        self.companion_device_infos[index] = device_info.clone();
        if let Err(err) = self.write_device_db() {
            log_e!("write_device_db fail:{:?}", err);
            self.companion_device_infos[index] = device_info_old;
            return Err(err);
        }
        Ok(())
    }

    fn generate_unique_template_id(&self) -> Result<u64, ErrorCode> {
        log_i!("generate_unique_template_id start");
        self.generate_unique_id(move || self.companion_device_infos.as_slice(), |device| device.template_id)
    }

    fn add_token(&mut self, token_info: &CompanionTokenInfo) -> Result<(), ErrorCode> {
        log_i!("add_token start");
        if token_info.token.is_empty() {
            log_e!("Invalid token");
            return Err(ErrorCode::BadParam);
        }
        if self.get_device_index_by_template_id(token_info.template_id).is_none() {
            log_e!("template id not exists");
            return Err(ErrorCode::BadParam);
        }

        match self.get_token_index_by_template_info(token_info.template_id, token_info.device_type) {
            Some(index) => {
                self.companion_token_infos[index] = token_info.clone();
            },
            None => {
                if self.companion_token_infos.len() >= MAX_TOKEN_NUM {
                    log_e!("token num is reached limit");
                    return Err(ErrorCode::ExceedLimit);
                }
                self.companion_token_infos.push(token_info.clone());
                log_i!("Token added successfully for template_id: {:x}", token_info.template_id as u16);
            },
        }

        Ok(())
    }

    fn get_token(&self, template_id: u64, device_type: DeviceType) -> Result<CompanionTokenInfo, ErrorCode> {
        log_i!("get_token start");
        self.get_token_index_by_template_info(template_id, device_type)
            .map(|index| self.companion_token_infos[index].clone())
            .ok_or_else(|| {
                log_e!("Token not found for template_id: {:x}", template_id as u16);
                ErrorCode::NotFound
            })
    }

    fn remove_token(&mut self, template_id: u64, device_type: DeviceType) -> Result<CompanionTokenInfo, ErrorCode> {
        log_i!("remove_token start");
        self.get_token_index_by_template_info(template_id, device_type)
            .map(|index| {
                let token = self.companion_token_infos.remove(index);
                log_i!("Token removed successfully for template_id: {:x}", template_id as u16);
                token
            })
            .ok_or_else(|| {
                log_i!("Token not found for removal, template_id: {:x}", template_id as u16);
                ErrorCode::NotFound
            })
    }

    fn update_token(&mut self, token_info: &CompanionTokenInfo) -> Result<(), ErrorCode> {
        log_i!("update_token start");
        if let Some(index) = self.get_token_index_by_template_info(token_info.template_id, token_info.device_type) {
            self.companion_token_infos[index] = token_info.clone();
            log_i!(
                "Token updated successfully for template_id: {:x}, device_type: {:?}",
                token_info.template_id as u16,
                token_info.device_type
            );
            Ok(())
        } else {
            log_e!(
                "Token not found for update, template_id: {:x}, device_type: {:?}",
                token_info.template_id as u16,
                token_info.device_type
            );
            Err(ErrorCode::NotFound)
        }
    }

    fn read_device_db(&mut self) -> Result<(), ErrorCode> {
        log_i!("read_device_db start");
        let device_data: Vec<u8> = StorageIoRegistry::get().read(HOST_DEVICE_DB).map_err(|e| p!(e))?;
        if device_data.is_empty() {
            log_i!("device db is empty");
            return Ok(());
        }

        let mut parcel = Parcel::from(device_data);
        if let Err(err) = self.deserialize_device_db(&mut parcel) {
            log_e!("deserialize_device_db fail:{:?}", err);
            self.companion_device_infos.clear();
            return Err(err);
        }
        Ok(())
    }

    fn read_device_base_info(&self, template_id: u64) -> Result<CompanionDeviceBaseInfo, ErrorCode> {
        log_i!("read_device_base_info start, template_id:{:x}", template_id as u16);
        let filename = format!("{:x}_{}", template_id, HOST_DEVICE_BASE_INFO);
        let base_info_data: Vec<u8> = StorageIoRegistry::get().read(&filename).map_err(|e| p!(e))?;
        if base_info_data.is_empty() {
            log_i!("device base info is empty");
            return Err(ErrorCode::GeneralError);
        }

        let mut parcel = Parcel::from(base_info_data);
        self.deserialize_device_base_info(&mut parcel)
    }

    fn write_device_base_info(&self, template_id: u64, base_info: &CompanionDeviceBaseInfo) -> Result<(), ErrorCode> {
        log_i!("write_device_base_info start, template_id:{:x}", template_id as u16);
        let filename = format!("{:x}_{}", template_id, HOST_DEVICE_BASE_INFO);
        let mut parcel = Parcel::new();
        self.serialize_device_base_info(base_info, &mut parcel)?;
        StorageIoRegistry::get()
            .write(&filename, parcel.as_slice())
            .map_err(|e| p!(e))?;
        Ok(())
    }

    fn delete_device_base_info(&self, template_id: u64) -> Result<(), ErrorCode> {
        log_i!("delete_device_base_info start, template_id:{:x}", template_id as u16);
        let filename = format!("{:x}_{}", template_id, HOST_DEVICE_BASE_INFO);
        StorageIoRegistry::get().delete(&filename).map_err(|e| p!(e))?;
        Ok(())
    }

    fn read_device_capability_info(&self, template_id: u64) -> Result<Vec<CompanionDeviceCapability>, ErrorCode> {
        log_i!("read_device_capability_info start, template_id:{:x}", template_id as u16);
        let filename = format!("{:x}_{}", template_id, HOST_DEVICE_CAPABILTY_INFO);
        let capability_info_data: Vec<u8> = StorageIoRegistry::get().read(&filename).map_err(|e| p!(e))?;
        if capability_info_data.is_empty() {
            log_i!("device capability info is empty");
            return Ok(Vec::new());
        }

        let mut parcel = Parcel::from(capability_info_data);
        self.deserialize_device_capability_info(&mut parcel)
    }

    fn write_device_capability_info(
        &self,
        template_id: u64,
        capability_info: &Vec<CompanionDeviceCapability>,
    ) -> Result<(), ErrorCode> {
        log_i!("write_device_capability_info start, template_id:{:x}", template_id as u16);
        let filename = format!("{:x}_{}", template_id, HOST_DEVICE_CAPABILTY_INFO);
        let mut parcel = Parcel::new();
        self.serialize_device_capability_info(capability_info, &mut parcel)?;
        StorageIoRegistry::get()
            .write(&filename, parcel.as_slice())
            .map_err(|e| p!(e))?;
        Ok(())
    }

    fn delete_device_capability_info(&self, template_id: u64) -> Result<(), ErrorCode> {
        log_i!("delete_device_capability_info start, template_id:{:x}", template_id as u16);
        let filename = format!("{:x}_{}", template_id, HOST_DEVICE_CAPABILTY_INFO);
        StorageIoRegistry::get().delete(&filename).map_err(|e| p!(e))?;
        Ok(())
    }

    fn read_device_sk(&self, template_id: u64) -> Result<Vec<CompanionDeviceSk>, ErrorCode> {
        log_i!("read_device_sk start, template_id:{:x}", template_id as u16);
        let filename = format!("{:x}_{}", template_id, HOST_DEVICE_SK);
        let sk_info_data: Vec<u8> = StorageIoRegistry::get().read(&filename).map_err(|e| p!(e))?;
        if sk_info_data.is_empty() {
            log_i!("device capability info is empty");
            return Err(ErrorCode::GeneralError);
        }

        let mut parcel = Parcel::from(sk_info_data);
        self.deserialize_device_sk(&mut parcel)
    }

    fn write_device_sk(&self, template_id: u64, sk_info: &Vec<CompanionDeviceSk>) -> Result<(), ErrorCode> {
        log_i!("write_device_sk start, template_id:{:x}", template_id as u16);
        let filename = format!("{:x}_{}", template_id, HOST_DEVICE_SK);
        let mut parcel = Parcel::new();
        self.serialize_device_sk(sk_info, &mut parcel)?;
        StorageIoRegistry::get()
            .write(&filename, parcel.as_slice())
            .map_err(|e| p!(e))?;
        Ok(())
    }

    fn delete_device_sk(&self, template_id: u64) -> Result<(), ErrorCode> {
        log_i!("delete_device_sk start, template_id:{:x}", template_id as u16);
        let filename = format!("{:x}_{}", template_id, HOST_DEVICE_SK);
        StorageIoRegistry::get().delete(&filename).map_err(|e| p!(e))?;
        Ok(())
    }
}
