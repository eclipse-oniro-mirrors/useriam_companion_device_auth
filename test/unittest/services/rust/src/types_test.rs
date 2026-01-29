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

use crate::common::constants::{ErrorCode, UDID_LEN};
use crate::common::types::Udid;
use crate::log_i;
use crate::ut_registry_guard;

#[test]
fn udid_test() {
    let _guard = ut_registry_guard!();
    log_i!("udid_test start");

    assert_eq!(Udid::default().0, [0u8; UDID_LEN]);

    let valid_string = "a".repeat(UDID_LEN);
    assert_eq!(Udid::try_from(valid_string.clone()).unwrap().0, valid_string.as_bytes());

    let invalid_string = "a".repeat(UDID_LEN - 1);
    assert_eq!(Udid::try_from(invalid_string), Err(ErrorCode::BadParam));

    let valid_vec = vec![0xABu8; UDID_LEN];
    assert_eq!(Udid::try_from(&valid_vec).unwrap().0[..], valid_vec[..]);

    let invalid_vec = vec![0xABu8; UDID_LEN - 1];
    assert_eq!(Udid::try_from(&invalid_vec), Err(ErrorCode::BadParam));
}
