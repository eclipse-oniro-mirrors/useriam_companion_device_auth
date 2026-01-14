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
use crate::log_e;
use crate::singleton_registry;

pub trait TimeKeeper {
    fn get_system_time(&self) -> Result<u64, ErrorCode>;
    fn get_rtc_time(&self) -> Result<u64, ErrorCode>;
    fn get_ree_time(&self) -> Result<u64, ErrorCode>;
}

pub struct DummyTimeKeeper;

impl TimeKeeper for DummyTimeKeeper {
    fn get_system_time(&self) -> Result<u64, ErrorCode> {
        log_e!("get_system_time not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn get_rtc_time(&self) -> Result<u64, ErrorCode> {
        log_e!("get_rtc_time not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn get_ree_time(&self) -> Result<u64, ErrorCode> {
        log_e!("get_ree_time not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(TimeKeeperRegistry, TimeKeeper, DummyTimeKeeper);

#[cfg(any(test, feature = "test-utils"))]
pub use crate::test_utils::mock::MockTimeKeeper;
