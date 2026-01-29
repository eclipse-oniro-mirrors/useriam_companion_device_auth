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
use crate::log_i;
use crate::traits::time_keeper::{DummyTimeKeeper, TimeKeeper};
use crate::ut_registry_guard;

#[test]
fn dummy_time_keeper_test() {
    let _guard = ut_registry_guard!();
    log_i!("dummy_time_keeper_test start");

    let dummy_time_keeper = DummyTimeKeeper;
    assert_eq!(dummy_time_keeper.get_system_time(), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_time_keeper.get_rtc_time(), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_time_keeper.get_ree_time(), Err(ErrorCode::GeneralError));
}
