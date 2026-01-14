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
use crate::common::Udid;
use crate::log_i;
use crate::traits::crypto_engine::KeyPair;
use crate::traits::misc_manager::{DummyMiscManager, MiscManager};
use crate::ut_registry_guard;

#[test]
fn dummy_misc_manager_test() {
    let _guard = ut_registry_guard!();
    log_i!("dummy_misc_manager_test start");

    let mut dummy_misc_manager = DummyMiscManager;
    assert_eq!(dummy_misc_manager.get_distribute_key(Udid::default(), Udid::default()), Err(ErrorCode::GeneralError));
    assert_eq!(
        dummy_misc_manager.set_local_key_pair(KeyPair::new(Vec::<u8>::new(), Vec::<u8>::new())),
        Err(ErrorCode::GeneralError)
    );
    assert_eq!(dummy_misc_manager.get_local_key_pair(), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_misc_manager.set_fwk_pub_key(Vec::<u8>::new()), Err(ErrorCode::GeneralError));
    assert_eq!(dummy_misc_manager.get_fwk_pub_key(), Err(ErrorCode::GeneralError));
}
