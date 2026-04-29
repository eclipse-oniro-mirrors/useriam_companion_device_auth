/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

/// Per-file IDs for Rust security_command_adapter.
/// Range: 0x0200-0x02FF.
#[allow(non_camel_case_type)]
#[repr(u16)]
pub enum RustFileId {
    // entry/
    ENTRY = 0x0200,
    FFI = 0x0201,
    // commands/
    COMMON_COMMAND = 0x0210,
    SYSTEM_COMMANDS = 0x0211,
    // common/
    CONSTANTS = 0x0220,
    TYPES = 0x0221,
    // impls/
    DEFAULT_COMPANION_DEVICE_DB_MANAGER = 0x0230,
    DEFAULT_HOST_BINDING_DB_MANAGER = 0x0231,
    DEFAULT_MISC_MANAGER = 0x0232,
    DEFAULT_EVENT_MANAGER = 0x0233,
    DEFAULT_REQUEST_MANAGER = 0x0234,
    OPENSSL_CRYPTO_ENGINE = 0x0235,
    DEFAULT_STORAGE_IO = 0x0236,
    HILOG_LOGGER = 0x0237,
    // jobs/
    COMPANION_DEVICE_DB_HELPER = 0x0240,
    HOST_BINDING_DB_HELPER = 0x0241,
    MESSAGE_CRYPTO = 0x0242,
    // request/enroll/
    COMPANION_ENROLL = 0x0250,
    HOST_ENROLL = 0x0251,
    ENROLL_MESSAGE = 0x0252,
    // request/token_issue/
    COMPANION_ISSUE_TOKEN = 0x0260,
    HOST_ISSUE_TOKEN = 0x0261,
    TOKEN_ISSUE_MESSAGE = 0x0262,
    // request/token_auth/
    COMPANION_TOKEN_AUTH = 0x0270,
    HOST_TOKEN_AUTH = 0x0271,
    TOKEN_AUTH_MESSAGE = 0x0272,
    // request/token_obtain/
    COMPANION_OBTAIN_TOKEN = 0x0280,
    HOST_OBTAIN_TOKEN = 0x0281,
    TOKEN_OBTAIN_MESSAGE = 0x0282,
    // request/delegate_auth/
    COMPANION_DELEGATE_AUTH = 0x0290,
    HOST_DELEGATE_AUTH = 0x0291,
    DELEGATE_AUTH_MESSAGE = 0x0292,
    // request/status_sync/
    COMPANION_SYNC_STATUS = 0x02A0,
    HOST_SYNC_STATUS = 0x02A1,
    // request/jobs/
    COMMON_MESSAGE = 0x02B0,
    TOKEN_HELPER = 0x02B1,
    // traits/
    COMPANION_DEVICE_DB_MANAGER = 0x02C0,
    HOST_BINDING_DB_MANAGER = 0x02C1,
    CRYPTO_ENGINE = 0x02C2,
    EVENT_MANAGER = 0x02C3,
    MISC_MANAGER = 0x02C4,
    REQUEST_MANAGER = 0x02C5,
    STORAGE_IO = 0x02C6,
    TIME_KEEPER = 0x02C7,
    LOGGER = 0x02C8,
    // utils/ (0x02D0-0x02DF)
    ATTRIBUTE = 0x02D0,
    MESSAGE_CODEC = 0x02D1,
    PARCEL = 0x02D2,
}
