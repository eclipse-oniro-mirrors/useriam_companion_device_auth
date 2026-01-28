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

extern crate alloc;

use crate::common::constants::*;
use crate::entry::companion_device_auth_ffi::*;
use crate::traits::db_manager::DeviceKey;
use crate::traits::event_manager::*;
use crate::CString;
use crate::String;
use crate::Vec;
use crate::{log_e, p};
use core::convert::TryFrom;

// Common
pub fn try_vec_from_array_with_len<T: Clone>(array: &[T], len: u32) -> Result<Vec<T>, ErrorCode> {
    if len as usize > array.len() {
        log_e!("Invalid length: max {}, actual {}", len as usize, array.len());
        return Err(ErrorCode::BadParam);
    }
    Ok(array[..len as usize].to_vec())
}

pub fn try_array_from_vec<T: Default + Copy, const N: usize>(
    vec: Vec<T>,
) -> core::result::Result<([T; N], u32), ErrorCode> {
    if vec.len() > N {
        log_e!("Invalid length: max {}, actual {}", N, vec.len());
        return Err(ErrorCode::BadParam);
    }

    let len = vec.len() as u32;
    let mut array = [T::default(); N];
    for (i, item) in vec.into_iter().enumerate() {
        array[i] = item;
    }
    Ok((array, len))
}

// DataArray
macro_rules! impl_data_array {
    ($name:ident, $size:expr) => {
        impl $name {
            pub fn as_slice(&self) -> Result<&[u8], ErrorCode> {
                if self.len as usize > self.data.len() {
                    log_e!("Invalid length: max {}, actual {}", self.len as usize, self.data.len());
                    return Err(ErrorCode::BadParam);
                }
                Ok(&self.data[..self.len as usize])
            }

            pub fn to_vec(&self) -> Result<Vec<u8>, ErrorCode> {
                Ok(self.as_slice()?.to_vec())
            }

            pub fn to_string(&self) -> Result<String, ErrorCode> {
                String::from_utf8(self.to_vec()?).map_err(|_| ErrorCode::GeneralError)
            }
        }

        impl TryFrom<&Vec<u8>> for $name {
            type Error = ErrorCode;

            fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
                let (data, len) = try_array_from_vec::<u8, $size>(value.clone()).map_err(|e| p!(e))?;
                Ok($name { data, len })
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = ErrorCode;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(&value)
            }
        }

        impl TryFrom<CString> for $name {
            type Error = ErrorCode;

            fn try_from(value: CString) -> core::result::Result<Self, ErrorCode> {
                let bytes = value.as_bytes();
                let vec_bytes = bytes.to_vec();
                Self::try_from(&vec_bytes)
            }
        }
    };
}

impl_data_array!(DataArray64Ffi, MAX_DATA_LEN_64);
impl_data_array!(DataArray128Ffi, MAX_DATA_LEN_128);
impl_data_array!(DataArray256Ffi, MAX_DATA_LEN_256);
impl_data_array!(DataArray1024Ffi, MAX_DATA_LEN_1024);
impl_data_array!(DataArray20000Ffi, MAX_DATA_LEN_20000);

// DeviceKeyFfi
impl TryFrom<DeviceKey> for DeviceKeyFfi {
    type Error = ErrorCode;

    fn try_from(key: DeviceKey) -> Result<Self, ErrorCode> {
        let device_id = DataArray64Ffi::try_from(key.device_id.as_bytes().to_vec())?;

        Ok(DeviceKeyFfi { device_id, device_id_type: key.device_id_type, user_id: key.user_id })
    }
}

// String
impl TryFrom<String> for DataArray128Ffi {
    type Error = ErrorCode;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DataArray128Ffi::try_from(value.into_bytes())
    }
}

impl TryFrom<String> for DataArray256Ffi {
    type Error = ErrorCode;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DataArray256Ffi::try_from(value.into_bytes())
    }
}

// TemplateIdArrayFfi
impl TryFrom<TemplateIdArrayFfi> for Vec<u64> {
    type Error = ErrorCode;

    fn try_from(value: TemplateIdArrayFfi) -> core::result::Result<Self, ErrorCode> {
        let template_ids: Vec<u64> = try_vec_from_array_with_len(&value.data, value.len).map_err(|e| p!(e))?;
        Ok(template_ids)
    }
}

impl TryFrom<Vec<u64>> for TemplateIdArrayFfi {
    type Error = ErrorCode;

    fn try_from(value: Vec<u64>) -> core::result::Result<Self, ErrorCode> {
        let (data, len) = try_array_from_vec::<u64, MAX_TEMPLATE_ID_NUM_PER_USER_FFI>(value).map_err(|e| p!(e))?;
        Ok(TemplateIdArrayFfi { data, len })
    }
}

// Uint16Array64Ffi
impl TryFrom<Uint16Array64Ffi> for Vec<u16> {
    type Error = ErrorCode;

    fn try_from(value: Uint16Array64Ffi) -> core::result::Result<Self, ErrorCode> {
        let u16_vec: Vec<u16> = try_vec_from_array_with_len(&value.data, value.len).map_err(|e| p!(e))?;
        Ok(u16_vec)
    }
}

impl TryFrom<Vec<u16>> for Uint16Array64Ffi {
    type Error = ErrorCode;

    fn try_from(value: Vec<u16>) -> core::result::Result<Self, ErrorCode> {
        let (data, len) = try_array_from_vec::<u16, MAX_DATA_LEN_64>(value).map_err(|e| p!(e))?;
        Ok(Uint16Array64Ffi { data, len })
    }
}

// Int32Array64Ffi
impl TryFrom<Int32Array64Ffi> for Vec<i32> {
    type Error = ErrorCode;

    fn try_from(value: Int32Array64Ffi) -> core::result::Result<Self, ErrorCode> {
        let i32_vec: Vec<i32> = try_vec_from_array_with_len(&value.data, value.len).map_err(|e| p!(e))?;
        Ok(i32_vec)
    }
}

impl TryFrom<Vec<i32>> for Int32Array64Ffi {
    type Error = ErrorCode;

    fn try_from(value: Vec<i32>) -> core::result::Result<Self, ErrorCode> {
        let (data, len) = try_array_from_vec::<i32, MAX_DATA_LEN_64>(value).map_err(|e| p!(e))?;
        Ok(Int32Array64Ffi { data, len })
    }
}

pub fn companion_status_vec_to_ffi(
    vec: Vec<PersistedCompanionStatusFfi>,
    ffi: &mut CompanionStatusArrayFfi,
) -> Result<(), ErrorCode> {
    let len = vec.len();
    if len > MAX_TEMPLATE_ID_NUM_PER_USER_FFI {
        return Err(ErrorCode::GeneralError);
    }

    ffi.len = len as u32;
    for (i, item) in vec.into_iter().enumerate() {
        ffi.data[i] = item;
    }
    Ok(())
}

pub fn host_binding_status_vec_to_ffi(
    vec: Vec<PersistedHostBindingStatusFfi>,
    ffi: &mut HostBindingStatusArrayFfi,
) -> Result<(), ErrorCode> {
    let len = vec.len();
    if len > MAX_TEMPLATE_ID_NUM_PER_USER_FFI {
        return Err(ErrorCode::GeneralError);
    }

    ffi.len = len as u32;
    for (i, item) in vec.into_iter().enumerate() {
        ffi.data[i] = item;
    }
    Ok(())
}

// CommonOutput
#[derive(Clone, Default)]
pub struct CommonOutput {
    pub result: ErrorCode,
    pub has_fatal_error: bool,
    pub events: Vec<Event>,
}

impl TryFrom<CommonOutput> for CommonOutputFfi {
    type Error = ErrorCode;

    fn try_from(value: CommonOutput) -> core::result::Result<Self, ErrorCode> {
        Ok(CommonOutputFfi {
            result: value.result as i32,
            has_fatal_error: value.has_fatal_error as u8,
            events: value.events.try_into().map_err(|e| p!(e))?,
        })
    }
}

impl TryFrom<Event> for EventFfi {
    type Error = ErrorCode;

    fn try_from(value: Event) -> core::result::Result<Self, ErrorCode> {
        Ok(EventFfi {
            time: value.time,
            file_name: value.file_name.try_into().map_err(|e| p!(e))?,
            line_number: value.line_number,
            event_type: value.event_type as i32,
            event_info: value.event_info.try_into().map_err(|e| p!(e))?,
        })
    }
}

impl TryFrom<Vec<Event>> for EventArrayFfi {
    type Error = ErrorCode;

    fn try_from(value: Vec<Event>) -> core::result::Result<Self, ErrorCode> {
        let mut data = [EventFfi::default(); MAX_EVENT_NUM_FFI];
        for (i, item) in value.iter().enumerate() {
            data[i] = item.clone().try_into().map_err(|e| p!(e))?;
        }

        Ok(EventArrayFfi { data, len: value.len() as u32 })
    }
}
