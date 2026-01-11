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
use crate::log_e;
use crate::String;
use crate::Vec;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd)]
pub struct Udid(pub [u8; UDID_LEN]);

impl Default for Udid {
    fn default() -> Self {
        Udid([0; UDID_LEN])
    }
}

impl TryFrom<String> for Udid {
    type Error = ErrorCode;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != UDID_LEN {
            log_e!("udid length mismatch, expected: {}, actual: {}", UDID_LEN, value.len());
            return Err(ErrorCode::BadParam);
        }

        let mut udid = [0u8; UDID_LEN];
        udid.copy_from_slice(value.as_bytes());
        Ok(Udid(udid))
    }
}

impl core::fmt::Debug for Udid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Udid({:02X?}...{:02X?})", &self.0[..2], &self.0[UDID_LEN - 2..])
    }
}

pub type Uuid = [u8; UDID_LEN];

impl TryFrom<&Vec<u8>> for Udid {
    type Error = ErrorCode;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != UDID_LEN {
            log_e!("udid length mismatch, expected: {}, actual: {}", UDID_LEN, value.len());
            return Err(ErrorCode::BadParam);
        }
        let mut udid = [0u8; UDID_LEN];
        udid.copy_from_slice(&value);
        Ok(Udid(udid))
    }
}
