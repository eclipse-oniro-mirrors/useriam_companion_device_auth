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

use rust::{log_i, log_d};
use rust::vec;
use rust::Vec;
use alloc::boxed::Box;
use rust::utils::scope_guard;
use rust::ut_registry_guard;

#[test]
fn scope_guard_test() {
    let _guard = ut_registry_guard!();
    log_i!("scope_guard_test start");

    let callback: Box<dyn FnOnce()> = Box::new(|| {});
    let mut scope_guard = ScopeGuard::new(callback);

    let callback: Box<dyn FnOnce()> = Box::new(|| {});
    scope_guard.add_callback(callback);

    scope_guard.cancel();
    assert_eq!(scope_guard.is_cancelled(), true);
}

#[test]
fn scope_guard_drop_test() {
    let _guard = ut_registry_guard!();
    log_i!("scope_guard_drop_test start");

    let callback: Box<dyn FnOnce()> = Box::new(|| {});
    let _scope_gurad = ScopeGuard::new(callback);
}