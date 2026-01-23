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

#![cfg_attr(not(any(test, feature = "test-utils")), no_std)]

#[cfg(any(test, feature = "test-utils"))]
extern crate self as companion_device_auth;

pub mod commands;
pub mod common;
pub mod entry;
pub mod impls;
pub mod jobs;
pub mod request;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
#[macro_use]
pub mod traits;
pub mod utils;

#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) extern crate alloc;

#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) use alloc::{
    boxed::Box, collections::BTreeMap, ffi::CString, fmt::Arguments, string::String, vec, vec::Vec,
};

#[cfg(any(test, feature = "test-utils"))]
pub(crate) use std::{boxed::Box, collections::BTreeMap, ffi::CString, fmt::Arguments, string::String, vec, vec::Vec};

pub(crate) use common::*;

// Re-export commonly used types and macros for tests
#[cfg(any(test, feature = "test-utils"))]
pub use {
    common::constants::SHA256_DIGEST_SIZE, traits::crypto_engine::MockCryptoEngine,
    traits::misc_manager::MockMiscManager,
};

// Unit tests configuration
#[cfg(any(test, feature = "test-utils"))]
#[path = "../../../test/unittest/services/rust/src/unit_test.rs"]
mod unit_test;
