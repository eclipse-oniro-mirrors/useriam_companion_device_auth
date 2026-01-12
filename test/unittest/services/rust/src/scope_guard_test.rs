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

use crate::log_i;
use crate::utils::scope_guard::ScopeGuard;
use crate::ut_registry_guard;

static mut TEST: i32 = 0;

#[test]
fn scope_guard_test() {
    let _guard = ut_registry_guard!();
    log_i!("scope_guard_test start");

    unsafe {
        TEST = 0;
        {
            ScopeGuard::new(Box::new(|| {
                TEST += 1;
            }));
        }
        assert_eq!(TEST, 1);
        {
            let mut scope_guard = ScopeGuard::new(Box::new(|| {
                TEST += 1;
            }));
            scope_guard.add_callback(Box::new(|| {
                TEST += 1;
            }));
        }
        assert_eq!(TEST, 3);
        {
            let mut scope_guard = ScopeGuard::new(Box::new(|| {
                TEST += 1;
            }));
            assert_eq!(scope_guard.is_cancelled(), false);
            scope_guard.cancel();
            assert_eq!(scope_guard.is_cancelled(), true);
        }
    }
}