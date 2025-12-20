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

use crate::singleton_registry;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LogLevel {
    DEBUG,
    INFO,
    ERROR,
}

impl core::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LogLevel::DEBUG => write!(f, "D"),
            LogLevel::INFO => write!(f, "I"),
            LogLevel::ERROR => write!(f, "E"),
        }
    }
}

pub trait Logger {
    fn log(&self, level: LogLevel, file_path: &str, line_num: u32, args: crate::Arguments<'_>);
}

struct DummyLogger;

impl Logger for DummyLogger {
    fn log(&self, _level: LogLevel, _file_path: &str, _line_num: u32, _args: crate::Arguments<'_>) {
    }
}

singleton_registry!(LoggerRegistry, Logger, DummyLogger);

#[inline]
pub fn get_logger() -> &'static crate::Box<dyn Logger> {
    LoggerRegistry::get()
}

#[macro_export]
macro_rules! log_d {
    ($($arg:tt)*) => {
        {
            $crate::traits::logger::get_logger().log(
                $crate::traits::logger::LogLevel::DEBUG,
                file!(),
                line!(),
                format_args!($($arg)*)
            );
        }
    }
}

#[macro_export]
macro_rules! log_i {
    ($($arg:tt)*) => {
        {
            $crate::traits::logger::get_logger().log(
                $crate::traits::logger::LogLevel::INFO,
                file!(),
                line!(),
                format_args!($($arg)*)
            );
        }
    }
}

#[macro_export]
macro_rules! log_e {
    ($($arg:tt)*) => {
        {
            $crate::traits::logger::get_logger().log(
                $crate::traits::logger::LogLevel::ERROR,
                file!(),
                line!(),
                format_args!($($arg)*)
            );
        }
    }
}

#[macro_export]
macro_rules! p {
    ($error:expr) => {{
        log_e!("propagating error");
        $error
    }};
}

#[macro_export]
macro_rules! unwrap_opt_or_return {
    ($expr:expr) => {
        match $expr {
            Some(value) => value,
            None => {
                log_e!("Option is None, return");
                return;
            }
        }
    };

    ($expr:expr, $error_code:expr) => {
        match $expr {
            Some(value) => value,
            None => {
                log_e!("Option is None, return {:?}", $error_code);
                return core::result::Result::Err($error_code);
            }
        }
    };
}

#[macro_export]
macro_rules! unwrap_or_return {
    ($expr:expr) => {
        match $expr {
            core::result::Result::Ok(value) => value,
            core::result::Result::Err(err) => {
                log_e!("Result is Err: {:?}, return", err);
                return;
            }
        }
    };
}

#[macro_export]
macro_rules! unwrap_or_return_val {
    ($expr:expr) => {
        match $expr {
            core::result::Result::Ok(value) => value,
            core::result::Result::Err(err) => {
                log_e!("Result is Err: {:?}, return {:?}", err, err);
                return core::result::Result::Err(err);
            }
        }
    };

    ($expr:expr, $error_code:expr) => {
        match $expr {
            core::result::Result::Ok(value) => value,
            core::result::Result::Err(err) => {
                log_e!("Result is Err: {:?}, return {:?}", err, $error_code);
                return core::result::Result::Err($error_code);
            }
        }
    };
}

#[macro_export]
macro_rules! ensure_or_return_val {
    ($expr1:expr) => {{
        if !$expr1 {
            log_e!(
                "Assertion failed: {} (value: {:?})",
                stringify!($expr1),
                $expr1
            );
            return;
        }
    }};

    ($expr1:expr, $return_val:expr) => {{
        if !$expr1 {
            log_e!(
                "Assertion failed: {} (value: {:?}), return {:?}",
                stringify!($expr1),
                $expr1,
                $return_val
            );
            return core::result::Result::Err($return_val);
        }
    }};
}
