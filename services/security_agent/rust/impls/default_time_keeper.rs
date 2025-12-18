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
use crate::traits::time_keeper::TimeKeeper;

pub struct DefaultTimeKeeper;

const CLOCK_REALTIME: u32 = 0;
const CLOCK_MONOTONIC: u32 = 1;

impl DefaultTimeKeeper {
    pub fn new() -> Self {
        Self
    }

    fn get_clock_time(&self, clock_id: u32) -> Result<u64, ErrorCode> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };

        if unsafe { libc::clock_gettime(clock_id as i32, &mut ts) } != 0 {
            return Err(ErrorCode::GeneralError);
        }

        Ok(ts.tv_sec as u64 * 1000 + (ts.tv_nsec / 1_000_000) as u64)
    }
}

impl TimeKeeper for DefaultTimeKeeper {
    fn get_system_time(&self) -> Result<u64, ErrorCode> {
        self.get_clock_time(CLOCK_MONOTONIC)
    }

    fn get_rtc_time(&self) -> Result<u64, ErrorCode> {
        self.get_clock_time(CLOCK_REALTIME)
    }

    fn get_ree_time(&self) -> Result<u64, ErrorCode> {
        self.get_clock_time(CLOCK_REALTIME)
    }
}

impl Default for DefaultTimeKeeper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_functions() {
        let keeper = DefaultTimeKeeper::new();

        // 测试系统时间获取（单调递增）
        let system_time = keeper.get_system_time().unwrap();
        assert!(system_time > 0);

        // 测试RTC时间获取（单调递增）
        let rtc_time = keeper.get_rtc_time().unwrap();
        assert!(rtc_time > 0);

        // 测试REE时间获取（墙上时钟）
        let ree_time = keeper.get_ree_time().unwrap();
        assert!(ree_time > 0);

        // 测试单调时间的递增性
        let system_time2 = keeper.get_system_time().unwrap();
        assert!(system_time2 >= system_time);

        // 测试RTC时间的递增性
        let rtc_time2 = keeper.get_rtc_time().unwrap();
        assert!(rtc_time2 >= rtc_time);
    }
}
