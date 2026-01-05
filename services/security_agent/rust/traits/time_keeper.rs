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
#[cfg(any(test, feature = "test-utils"))]
use mockall::automock;

/// 时间获取器trait
#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait TimeKeeper {
    /// 获取系统时间
    fn get_system_time(&self) -> Result<u64, ErrorCode>;

    /// 获取RTC时间
    fn get_rtc_time(&self) -> Result<u64, ErrorCode>;

    /// 获取REE时间
    fn get_ree_time(&self) -> Result<u64, ErrorCode>;
}

/// 默认时间获取器实现
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_time_keeper_test() {
        let dummy_time_keeper = DummyTimeKeeper;
        assert_eq!(dummy_time_keeper.get_system_time(), Err(ErrorCode::GeneralError));
        assert_eq!(dummy_time_keeper.get_rtc_time(), Err(ErrorCode::GeneralError));
        assert_eq!(dummy_time_keeper.get_ree_time(), Err(ErrorCode::GeneralError));
    }
}
