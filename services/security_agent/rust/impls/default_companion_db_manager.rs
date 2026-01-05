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
use crate::traits::companion_db_manager::{CompanionDbManager, HostDeviceFilter};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::{DeviceKey, HostDeviceInfo, HostDeviceSk, HostTokenInfo, UserInfo};
use crate::traits::storage_io::StorageIoRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::parcel::Parcel;
use crate::vec;
use crate::String;
use crate::{log_e, log_i, p, singleton_registry, Box, Vec};
use alloc::format;
use core::mem;

pub const CURRENT_VERSION: i32 = 0;
pub const MAX_TOKEN_LENGTH: i32 = 32;
pub const COMPANION_DEVICE_DB: &str = "host_device_db";
pub const COMPANION_DEVICE_SK: &str = "host_device_sk";
pub const COMPANION_DEVICE_TOKEN: &str = "host_device_token";

pub const MAX_DEVICE_NUM: usize = 5;
pub const MAX_DEVICE_NUM_PER_USER: usize = 1;

pub struct DefaultCompaniomDbManager {
    pub host_device_infos: Vec<HostDeviceInfo>,
}

impl DefaultCompaniomDbManager {
    pub fn new() -> Self {
        DefaultCompaniomDbManager { host_device_infos: Vec::with_capacity(MAX_DEVICE_NUM) }
    }

    fn get_index_by_binding_id(&self, binding_id: i32) -> Option<usize> {
        self.host_device_infos
            .iter()
            .position(|device_info| device_info.binding_id == binding_id)
    }

    fn get_index_by_device_key(&self, user_id: i32, device_key: &DeviceKey) -> Option<usize> {
        self.host_device_infos
            .iter()
            .position(|device_info| device_key == &device_info.device_key && user_id == device_info.user_info.user_id)
    }

    fn generate_unique_id<'a, T, F, G>(&'a self, collection: F, id_extractor: G) -> Result<i32, ErrorCode>
    where
        T: 'a,
        F: Fn() -> &'a [T] + 'a,
        G: Fn(&T) -> i32 + 'a,
    {
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 100;

        loop {
            let mut random_bytes = [0u8; 4];
            CryptoEngineRegistry::get().secure_random(&mut random_bytes).map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

            let random = i32::from_le_bytes(random_bytes);

            let exists = collection().iter().any(|item| id_extractor(item) == random);
            if !exists {
                return Ok(random);
            }

            attempts += 1;
            if attempts >= MAX_ATTEMPTS {
                log_e!("Failed to generate unique ID after {} attempts", MAX_ATTEMPTS);
                return Err(ErrorCode::GeneralError);
            }
        }
    }

    fn serialize_device_db(&self, parcel: &mut Parcel) -> Result<(), ErrorCode> {
        parcel.write_i32(CURRENT_VERSION);
        parcel.write_i32(self.host_device_infos.len() as i32);

        for host_device_info in &self.host_device_infos {
            parcel.write_string(&host_device_info.device_key.device_id);
            parcel.write_i32(host_device_info.device_key.device_id_type);
            parcel.write_i32(host_device_info.device_key.user_id);
            parcel.write_i32(host_device_info.binding_id);
            parcel.write_i32(host_device_info.user_info.user_id);
            parcel.write_i32(host_device_info.user_info.user_type);
            parcel.write_u64(host_device_info.binding_time);
            parcel.write_u64(host_device_info.last_used_time);
        }

        Ok(())
    }

    fn deserialize_device_db(&mut self, parcel: &mut Parcel) -> Result<(), ErrorCode> {
        let _version = match parcel.read_i32() {
            Ok(version) => version,
            Err(_) => return Err(ErrorCode::ReadParcelError),
        };

        self.host_device_infos.clear();
        let count = match parcel.read_i32() {
            Ok(count) if count >= 0 => count as usize,
            _ => return Err(ErrorCode::ReadParcelError),
        };

        for _ in 0..count {
            let device_id = parcel.read_string().map_err(|e| p!(e))?;
            let device_id_type = parcel.read_i32().map_err(|e| p!(e))?;
            let user_id = parcel.read_i32().map_err(|e| p!(e))?;
            let binding_id = parcel.read_i32().map_err(|e| p!(e))?;
            let user_info_user_id = parcel.read_i32().map_err(|e| p!(e))?;
            let user_info_user_type = parcel.read_i32().map_err(|e| p!(e))?;
            let binding_time = parcel.read_u64().map_err(|e| p!(e))?;
            let last_used_time = parcel.read_u64().map_err(|e| p!(e))?;

            let host_device_info = HostDeviceInfo {
                device_key: DeviceKey { device_id, device_id_type, user_id },
                binding_id,
                user_info: UserInfo { user_id: user_info_user_id, user_type: user_info_user_type },
                binding_time,
                last_used_time,
            };
            self.host_device_infos.push(host_device_info);
        }

        Ok(())
    }

    fn serialize_token_info(&self, host_token_info: &HostTokenInfo, parcel: &mut Parcel) -> Result<(), ErrorCode> {
        parcel.write_i32(CURRENT_VERSION);
        parcel.write_i32(host_token_info.token.len() as i32);
        parcel.write_bytes(&host_token_info.token);
        parcel.write_i32(host_token_info.atl as i32);
        Ok(())
    }

    fn deserialize_token_info(&self, parcel: &mut Parcel) -> Result<HostTokenInfo, ErrorCode> {
        let version = parcel.read_i32().map_err(|_| ErrorCode::ReadParcelError)?;
        if version > CURRENT_VERSION {
            log_e!("db_version is error, db_version:{}, current_version:{}", version, CURRENT_VERSION);
            return Err(ErrorCode::GeneralError);
        }
        let token_len = parcel.read_i32().map_err(|e| p!(e))? as usize;
        let mut token = vec![0u8; token_len];
        parcel.read_bytes(&mut token).map_err(|e| p!(e))?;
        let atl_value = parcel.read_i32().map_err(|e| p!(e))?;
        let atl = AuthTrustLevel::try_from(atl_value).map_err(|e| p!(e))?;
        let host_token_info = HostTokenInfo { token, atl };
        Ok(host_token_info)
    }

    fn serialize_device_sk(&self, sk_info: &HostDeviceSk, parcel: &mut Parcel) -> Result<(), ErrorCode> {
        parcel.write_i32(CURRENT_VERSION);
        parcel.write_i32(sk_info.sk.len() as i32);
        parcel.write_bytes(&sk_info.sk);
        Ok(())
    }

    fn deserialize_device_sk(&self, parcel: &mut Parcel) -> Result<HostDeviceSk, ErrorCode> {
        let _version = parcel.read_i32().map_err(|_| ErrorCode::ReadParcelError)?;
        let sk_len = parcel.read_i32().map_err(|e| p!(e))? as usize;
        let mut sk = vec![0u8; sk_len];
        parcel.read_bytes(&mut sk).map_err(|e| p!(e))?;
        let sk_info = HostDeviceSk { sk };
        Ok(sk_info)
    }

    fn write_device_db(&self) -> Result<(), ErrorCode> {
        log_i!("write_device_db start");
        let mut parcel = Parcel::new();
        self.serialize_device_db(&mut parcel)?;
        StorageIoRegistry::get()
            .write(&COMPANION_DEVICE_DB, parcel.as_slice())
            .map_err(|e| p!(e))?;
        Ok(())
    }

    fn get_device_num_by_user_id(&self, user_id: i32) -> usize {
        self.host_device_infos
            .iter()
            .filter(|device| device.user_info.user_id == user_id)
            .count()
    }

    fn remove_oldest_unused_device(&mut self, user_id: i32) -> Result<(), ErrorCode> {
        let user_devices: Vec<(usize, &HostDeviceInfo)> = self
            .host_device_infos
            .iter()
            .enumerate()
            .filter(|(_, info)| info.user_info.user_id == user_id)
            .collect();

        if user_devices.is_empty() {
            log_i!("No devices found for user_id: {}", user_id);
            return Ok(());
        }

        let oldest_index = user_devices
            .iter()
            .min_by_key(|(_, info)| info.last_used_time)
            .map(|(index, _)| *index)
            .unwrap();

        let binding_id = self.host_device_infos[oldest_index].binding_id;
        self.delete_device_sk(binding_id)?;
        self.delete_device_token(binding_id)?;

        self.host_device_infos.remove(oldest_index);
        Ok(())
    }
}

impl CompanionDbManager for DefaultCompaniomDbManager {
    fn add_device(&mut self, device_info: &HostDeviceInfo, sk_info: &HostDeviceSk) -> Result<(), ErrorCode> {
        log_i!("add_device start");
        if device_info.device_key.device_id.is_empty() {
            log_e!("invalid device id");
            return Err(ErrorCode::BadParam);
        }

        if self
            .get_index_by_device_key(device_info.user_info.user_id, &device_info.device_key)
            .is_some()
        {
            log_e!("device key already exists");
            return Err(ErrorCode::BadParam);
        }

        let device_num = self.get_device_num_by_user_id(device_info.user_info.user_id);
        if device_num >= MAX_DEVICE_NUM_PER_USER {
            self.remove_oldest_unused_device(device_info.user_info.user_id)?;
        }

        if self.get_index_by_binding_id(device_info.binding_id).is_some() {
            log_e!("binding id already exists");
            return Err(ErrorCode::BadParam);
        }

        self.write_device_sk(device_info.binding_id, sk_info)?;
        self.host_device_infos.push(device_info.clone());
        let result = self.write_device_db();
        if result.is_ok() {
            return result;
        }
        log_e!("write_device_db fail");
        let _ = self.delete_device_sk(device_info.binding_id);
        if let Some(index) = self
            .host_device_infos
            .iter()
            .position(|d| d.binding_id == device_info.binding_id)
        {
            self.host_device_infos.remove(index);
        }
        result
    }

    fn get_device_by_binding_id(&self, binding_id: i32) -> Result<HostDeviceInfo, ErrorCode> {
        log_i!("get_device_by_binding_id start");
        self.get_index_by_binding_id(binding_id)
            .map(|index| self.host_device_infos[index].clone())
            .ok_or_else(|| {
                log_e!("No device matching filter found");
                ErrorCode::NotFound
            })
    }

    fn get_device_by_device_key(&self, user_id: i32, device_key: &DeviceKey) -> Result<HostDeviceInfo, ErrorCode> {
        log_i!("get_device_by_device_key start");
        self.get_index_by_device_key(user_id, device_key)
            .map(|index| self.host_device_infos[index].clone())
            .ok_or_else(|| {
                log_e!("No device matching filter found");
                ErrorCode::NotFound
            })
    }

    fn remove_device(&mut self, binding_id: i32) -> Result<HostDeviceInfo, ErrorCode> {
        log_i!("remove_device start");
        let find_result = self.get_index_by_binding_id(binding_id);
        match find_result {
            None => {
                log_i!("No device matching filter found for removal");
                Err(ErrorCode::NotFound)
            },
            Some(index) => {
                let device = self.host_device_infos.remove(index);
                if let Err(err) = self.write_device_db() {
                    log_e!("Failed to write device db after removal: {:?}", err);
                    self.host_device_infos.push(device);
                    return Err(err);
                }
                log_i!("Device removed successfully, binding_id: {}", device.binding_id);
                let _ = self.delete_device_sk(device.binding_id);
                let _ = self.delete_device_token(device.binding_id);
                Ok(device)
            },
        }
    }

    fn update_device(&mut self, device_info: &HostDeviceInfo) -> Result<(), ErrorCode> {
        log_i!("update_device start");
        let index1 = self.get_index_by_binding_id(device_info.binding_id).ok_or_else(|| {
            log_i!("No binding id matching");
            ErrorCode::NotFound
        })?;
        let index2 = self
            .get_index_by_device_key(device_info.user_info.user_id, &device_info.device_key)
            .ok_or_else(|| {
                log_i!("No device key matching");
                ErrorCode::NotFound
            })?;
        if index1 != index2 {
            log_e!("Binding id and device key do not match the same device");
            return Err(ErrorCode::BadParam);
        }
        let device_info_old = self.host_device_infos[index1].clone();
        self.host_device_infos[index1] = device_info.clone();
        let result = self.write_device_db();
        if result.is_err() {
            log_e!("write_device_db fail");
            self.host_device_infos[index1] = device_info_old;
        }
        result
    }

    fn generate_unique_binding_id(&self) -> Result<i32, ErrorCode> {
        log_i!("generate_unique_binding_id start");
        self.generate_unique_id(move || self.host_device_infos.as_slice(), |device| device.binding_id)
    }

    fn read_device_db(&mut self) -> Result<(), ErrorCode> {
        log_i!("read_device_db start");
        let device_infos: Vec<u8> = StorageIoRegistry::get().read(&COMPANION_DEVICE_DB).map_err(|e| p!(e))?;
        if device_infos.is_empty() {
            log_i!("db is empty");
            return Ok(());
        }

        let mut parcel = Parcel::from(device_infos);
        if let Err(err) = self.deserialize_device_db(&mut parcel) {
            log_e!("deserialize_device_db fail:{:?}", err);
            self.host_device_infos.clear();
            return Err(err);
        }
        Ok(())
    }

    fn read_device_token(&self, binding_id: i32) -> Result<HostTokenInfo, ErrorCode> {
        log_i!("read_device_token start, binding_id:{}", binding_id);
        let filename = format!("{:x}_{}", binding_id, COMPANION_DEVICE_TOKEN);
        let token_info: Vec<u8> = StorageIoRegistry::get().read(&filename).map_err(|e| p!(e))?;
        if token_info.is_empty() {
            log_i!("db is empty");
            return Err(ErrorCode::GeneralError);
        }
        let mut parcel = Parcel::from(token_info);
        self.deserialize_token_info(&mut parcel)
    }

    fn write_device_token(&self, binding_id: i32, token: &HostTokenInfo) -> Result<(), ErrorCode> {
        log_i!("write_device_token start, binding_id:{}", binding_id);
        let filename = format!("{:x}_{}", binding_id, COMPANION_DEVICE_TOKEN);
        let mut parcel = Parcel::new();
        self.serialize_token_info(token, &mut parcel)?;

        StorageIoRegistry::get().write(&filename, parcel.as_slice()).map_err(|e| p!(e))
    }

    fn delete_device_token(&self, binding_id: i32) -> Result<(), ErrorCode> {
        log_i!("delete_device_token start, binding_id:{}", binding_id);
        let filename = format!("{:x}_{}", binding_id, COMPANION_DEVICE_TOKEN);
        StorageIoRegistry::get().delete(&filename).map_err(|e| p!(e))
    }

    fn is_device_token_valid(&self, binding_id: i32) -> Result<bool, ErrorCode> {
        log_i!("is_device_token_valid start, binding_id:{}", binding_id);
        let filename = format!("{:x}_{}", binding_id, COMPANION_DEVICE_TOKEN);
        StorageIoRegistry::get().exists(&filename)
    }

    fn read_device_sk(&self, binding_id: i32) -> Result<HostDeviceSk, ErrorCode> {
        log_i!("read_device_sk start, binding_id:{}", binding_id);
        let filename = format!("{:x}_{}", binding_id, COMPANION_DEVICE_SK);
        let sk_info_data: Vec<u8> = StorageIoRegistry::get().read(&filename).map_err(|e| p!(e))?;
        if sk_info_data.is_empty() {
            log_i!("device sk info is empty");
            return Err(ErrorCode::GeneralError);
        }

        let mut parcel = Parcel::from(sk_info_data);
        self.deserialize_device_sk(&mut parcel)
    }

    fn write_device_sk(&self, binding_id: i32, sk_info: &HostDeviceSk) -> Result<(), ErrorCode> {
        log_i!("write_device_sk start, binding_id:{}", binding_id);
        let filename = format!("{:x}_{}", binding_id, COMPANION_DEVICE_SK);
        let mut parcel = Parcel::new();
        self.serialize_device_sk(sk_info, &mut parcel)?;
        StorageIoRegistry::get().write(&filename, parcel.as_slice()).map_err(|e| p!(e))
    }

    fn delete_device_sk(&self, binding_id: i32) -> Result<(), ErrorCode> {
        log_i!("delete_device_sk start, binding_id:{}", binding_id);
        let filename = format!("{:x}_{}", binding_id, COMPANION_DEVICE_SK);
        StorageIoRegistry::get().delete(&filename).map_err(|e| p!(e))
    }

    fn get_device_list(&self, user_id: i32) -> Vec<HostDeviceInfo> {
        log_i!("get_device_list start");
        self.host_device_infos
            .iter()
            .filter(|device_info| device_info.user_info.user_id == user_id)
            .cloned()
            .collect()
    }
}
