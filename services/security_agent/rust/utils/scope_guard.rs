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

use crate::log_d;
use crate::vec;
use crate::Vec;
use alloc::boxed::Box;

pub struct ScopeGuard {
    callbacks: Vec<Box<dyn FnOnce()>>,
    cancelled: bool,
}

impl ScopeGuard {
    pub fn new(callback: Box<dyn FnOnce()>) -> Self {
        Self { callbacks: vec![callback], cancelled: false }
    }

    pub fn add_callback(&mut self, callback: Box<dyn FnOnce()>) {
        self.callbacks.push(callback);
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        log_d!("guard cancelled");
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        if self.is_cancelled() {
            log_d!("guard is cancelled");
            return;
        }

        log_d!("guard trigger callbacks begin");
        for callback in self.callbacks.drain(..) {
            callback();
        }
        log_d!("guard trigger callbacks end");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut test: i32 = 0;

    #[test]
    fn scope_guard_test() {
        unsafe {
            test = 0;
            {
                ScopeGuard::new(Box::new(|| {
                    test += 1;
                }));
            }
            assert_eq!(test, 1);
            {
                let mut scopeGuard = ScopeGuard::new(Box::new(|| {
                    test += 1;
                }));
                scopeGuard.add_callback(Box::new(|| {
                    test += 1;
                }));
            }
            assert_eq!(test, 3);
            {
                let mut scopeGuard = ScopeGuard::new(Box::new(|| {
                    test += 1;
                }));
                assert_eq!(scopeGuard.is_cancelled(), false);
                scopeGuard.cancel();
                assert_eq!(scopeGuard.is_cancelled(), true);
            }
        }
    }
}
