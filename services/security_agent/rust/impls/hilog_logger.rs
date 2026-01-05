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

use crate::traits::logger::{LogLevel, Logger};
use crate::String;
use alloc::format;
use core::fmt;
use core::fmt::Write;
use std::ffi::{c_char, CStr, CString};

#[allow(unused_extern_crates)]
extern crate std;

use hilog_rust::{error, hilog, info, HiLogLabel, LogType};

const LOG_LABEL: HiLogLabel =
    HiLogLabel { log_type: LogType::LogCore, domain: 0xD002401, tag: "COMPANION_DEVICE_AUTH" };

pub struct HilogLogger;

impl HilogLogger {
    pub fn new() -> Self {
        HilogLogger
    }
}

impl Logger for HilogLogger {
    fn log(&self, level: LogLevel, file_path: &str, line_num: u32, args: fmt::Arguments<'_>) {
        let mut message = String::new();
        let _ = write!(&mut message, "{}", args);
        let file_name = if let Some(last_slash) = file_path.rfind('/') {
            let after_slash = last_slash + 1;
            if after_slash < file_path.len() {
                &file_path[after_slash..]
            } else {
                file_path
            }
        } else {
            file_path
        };
        match level {
            LogLevel::DEBUG => {
                hilog_rust::debug!(LOG_LABEL, "[{}:{}]{}", @public(file_name), @public(line_num), @public(message));
            },
            LogLevel::INFO => {
                hilog_rust::info!(LOG_LABEL, "[{}:{}]{}", @public(file_name), @public(line_num), @public(message));
            },
            LogLevel::ERROR => {
                hilog_rust::error!(LOG_LABEL, "[{}:{}]{}", @public(file_name), @public(line_num), @public(message));
            },
        }
    }
}
