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

//! Log trace buffer for capturing log_e! calls during command execution.
//! Single-threaded assumption: no synchronization needed.
//!
//! Each Rust file that uses log macros defines `const FILE_ID: u16 = RustFileId::XXX as u16;`
//! The macros reference FILE_ID at the call site via macro_rules! name resolution.

/// Per-file IDs for Rust security_command_adapter.
/// Range: 0x0200-0x02FF.
#[repr(u16)]
pub enum RustFileId {
    // entry/
    Entry = 0x0200,
    Ffi = 0x0201,
    // commands/
    CommonCommand = 0x0210,
    SystemCommands = 0x0211,
    // common/
    Constants = 0x0220,
    Types = 0x0221,
    // impls/
    DefaultCompanionDeviceDbManager = 0x0230,
    DefaultHostBindingDbManager = 0x0231,
    DefaultMiscManager = 0x0232,
    DefaultEventManager = 0x0233,
    DefaultRequestManager = 0x0234,
    OpensslCryptoEngine = 0x0235,
    DefaultStorageIo = 0x0236,
    HilogLogger = 0x0237,
    // jobs/
    CompanionDeviceDbHelper = 0x0240,
    HostBindingDbHelper = 0x0241,
    MessageCrypto = 0x0242,
    // request/enroll/
    CompanionEnroll = 0x0250,
    HostEnroll = 0x0251,
    EnrollMessage = 0x0252,
    // request/token_issue/
    CompanionIssueToken = 0x0260,
    HostIssueToken = 0x0261,
    TokenIssueMessage = 0x0262,
    // request/token_auth/
    CompanionTokenAuth = 0x0270,
    HostTokenAuth = 0x0271,
    TokenAuthMessage = 0x0272,
    // request/token_obtain/
    CompanionObtainToken = 0x0280,
    HostObtainToken = 0x0281,
    TokenObtainMessage = 0x0282,
    // request/delegate_auth/
    CompanionDelegateAuth = 0x0290,
    HostDelegateAuth = 0x0291,
    DelegateAuthMessage = 0x0292,
    // request/status_sync/
    CompanionSyncStatus = 0x02A0,
    HostSyncStatus = 0x02A1,
    // request/jobs/
    CommonMessage = 0x02B0,
    TokenHelper = 0x02B1,
    // traits/
    CompanionDeviceDbManager = 0x02C0,
    HostBindingDbManager = 0x02C1,
    CryptoEngine = 0x02C2,
    EventManager = 0x02C3,
    MiscManager = 0x02C4,
    RequestManager = 0x02C5,
    StorageIo = 0x02C6,
    TimeKeeper = 0x02C7,
    Logger = 0x02C8,
    // utils/
    Attribute = 0x02D0,
    MessageCodec = 0x02D1,
    Parcel = 0x02D2,
}

/// Per-file IDs for test files.
/// Range: 0x0300-0x03FF.
#[cfg(any(test, feature = "test-utils"))]
#[repr(u16)]
pub enum TestFileId {
    TypesTest = 0x0300,
    ConstantsTest = 0x0301,
    MessageCodecTest = 0x0303,
    AttributeTest = 0x0304,
    ParcelTest = 0x0305,
    CompanionDeviceAuthEntryTest = 0x0306,
    CompanionDeviceAuthFfiTest = 0x0307,
    CommonCommandTest = 0x0308,
    SystemCommandsTest = 0x0309,
    DefaultCompanionDeviceDbManagerTest = 0x030A,
    DefaultHostBindingDbManagerTest = 0x030B,
    DefaultMiscManagerTest = 0x030C,
    DefaultEventManagerTest = 0x030D,
    DefaultRequestManagerTest = 0x030E,
    OpensslCryptoEngineTest = 0x030F,
    DefaultStorageIoTest = 0x0310,
    CompanionDeviceDbHelperTest = 0x0311,
    HostBindingDbHelperTest = 0x0312,
    MessageCryptoTest = 0x0313,
    CompanionEnrollTest = 0x0314,
    HostEnrollTest = 0x0315,
    EnrollMessageTest = 0x0316,
    CompanionIssueTokenTest = 0x0317,
    HostIssueTokenTest = 0x0318,
    TokenIssueMessageTest = 0x0319,
    CompanionTokenAuthTest = 0x031A,
    HostTokenAuthTest = 0x031B,
    TokenAuthMessageTest = 0x031C,
    CompanionObtainTokenTest = 0x031D,
    HostObtainTokenTest = 0x031E,
    TokenObtainMessageTest = 0x031F,
    CompanionDelegateAuthTest = 0x0320,
    HostDelegateAuthTest = 0x0321,
    DelegateAuthMessageTest = 0x0322,
    CompanionSyncStatusTest = 0x0323,
    HostSyncStatusTest = 0x0324,
    CommonMessageTest = 0x0325,
    TokenHelperTest = 0x0326,
    CompanionDeviceDbManagerTest = 0x0327,
    HostBindingDbManagerTest = 0x0328,
    CryptoEngineTest = 0x0329,
    EventManagerTest = 0x032A,
    MiscManagerTest = 0x032B,
    RequestManagerTest = 0x032C,
    StorageIoTest = 0x032D,
    TimeKeeperTest = 0x032E,
    AuthTokenTest = 0x032F,
}

/// Map a file_id back to its short filename for log output.
pub fn file_id_to_name(file_id: u16) -> &'static str {
    match file_id {
        // entry/ — Entry, Ffi
        0x0200 => "companion_device_auth_entry.rs",
        0x0201 => "companion_device_auth_ffi.rs",
        // commands/ — CommonCommand, SystemCommands
        0x0210 => "common_command.rs",
        0x0211 => "system_commands.rs",
        // common/ — Constants, Types
        0x0220 => "constants.rs",
        0x0221 => "types.rs",
        // impls/ — Default*DbManager .. HilogLogger
        0x0230 => "default_companion_device_db_manager.rs",
        0x0231 => "default_host_binding_db_manager.rs",
        0x0232 => "default_misc_manager.rs",
        0x0233 => "default_event_manager.rs",
        0x0234 => "default_request_manager.rs",
        0x0235 => "openssl_crypto_engine.rs",
        0x0236 => "default_storage_io.rs",
        0x0237 => "hilog_logger.rs",
        // jobs/ — *DbHelper, MessageCrypto
        0x0240 => "companion_device_db_helper.rs",
        0x0241 => "host_binding_db_helper.rs",
        0x0242 => "message_crypto.rs",
        // request/enroll/ — CompanionEnroll, HostEnroll, EnrollMessage
        0x0250 => "companion_enroll.rs",
        0x0251 => "host_enroll.rs",
        0x0252 => "enroll_message.rs",
        // request/token_issue/
        0x0260 => "companion_issue_token.rs",
        0x0261 => "host_issue_token.rs",
        0x0262 => "token_issue_message.rs",
        // request/token_auth/
        0x0270 => "companion_token_auth.rs",
        0x0271 => "host_token_auth.rs",
        0x0272 => "token_auth_message.rs",
        // request/token_obtain/
        0x0280 => "companion_obtain_token.rs",
        0x0281 => "host_obtain_token.rs",
        0x0282 => "token_obtain_message.rs",
        // request/delegate_auth/
        0x0290 => "companion_delegate_auth.rs",
        0x0291 => "host_delegate_auth.rs",
        0x0292 => "delegate_auth_message.rs",
        // request/status_sync/
        0x02A0 => "companion_sync_status.rs",
        0x02A1 => "host_sync_status.rs",
        // request/jobs/
        0x02B0 => "common_message.rs",
        0x02B1 => "token_helper.rs",
        // traits/
        0x02C0 => "companion_device_db_manager.rs",
        0x02C1 => "host_binding_db_manager.rs",
        0x02C2 => "crypto_engine.rs",
        0x02C3 => "event_manager.rs",
        0x02C4 => "misc_manager.rs",
        0x02C5 => "request_manager.rs",
        0x02C6 => "storage_io.rs",
        0x02C7 => "time_keeper.rs",
        0x02C8 => "logger.rs",
        // utils/
        0x02D0 => "attribute.rs",
        0x02D1 => "message_codec.rs",
        0x02D2 => "parcel.rs",
        _ => test_file_id_to_name(file_id),
    }
}

#[cfg(not(any(test, feature = "test-utils")))]
fn test_file_id_to_name(_: u16) -> &'static str {
    "unknown"
}

#[cfg(any(test, feature = "test-utils"))]
fn test_file_id_to_name(file_id: u16) -> &'static str {
    match file_id {
        0x0300 => "types_test.rs",           // TypesTest
        0x0301 => "constants_test.rs",       // ConstantsTest
        0x0303 => "message_codec_test.rs",   // MessageCodecTest
        0x0304 => "attribute_test.rs",       // AttributeTest
        0x0305 => "parcel_test.rs",          // ParcelTest
        0x0306 => "companion_device_auth_entry_test.rs",
        0x0307 => "companion_device_auth_ffi_test.rs",
        0x0308 => "common_command_test.rs",
        0x0309 => "system_commands_test.rs",
        0x030A => "default_companion_device_db_manager_test.rs",
        0x030B => "default_host_binding_db_manager_test.rs",
        0x030C => "default_misc_manager_test.rs",
        0x030D => "default_event_manager_test.rs",
        0x030E => "default_request_manager_test.rs",
        0x030F => "openssl_crypto_engine_test.rs",
        0x0310 => "default_storage_io_test.rs",
        0x0311 => "companion_device_db_helper_test.rs",
        0x0312 => "host_binding_db_helper_test.rs",
        0x0313 => "message_crypto_test.rs",
        0x0314 => "companion_enroll_test.rs",
        0x0315 => "host_enroll_test.rs",
        0x0316 => "enroll_message_test.rs",
        0x0317 => "companion_issue_token_test.rs",
        0x0318 => "host_issue_token_test.rs",
        0x0319 => "token_issue_message_test.rs",
        0x031A => "companion_token_auth_test.rs",
        0x031B => "host_token_auth_test.rs",
        0x031C => "token_auth_message_test.rs",
        0x031D => "companion_obtain_token_test.rs",
        0x031E => "host_obtain_token_test.rs",
        0x031F => "token_obtain_message_test.rs",
        0x0320 => "companion_delegate_auth_test.rs",
        0x0321 => "host_delegate_auth_test.rs",
        0x0322 => "delegate_auth_message_test.rs",
        0x0323 => "companion_sync_status_test.rs",
        0x0324 => "host_sync_status_test.rs",
        0x0325 => "common_message_test.rs",
        0x0326 => "token_helper_test.rs",
        0x0327 => "companion_device_db_manager_test.rs",
        0x0328 => "host_binding_db_manager_test.rs",
        0x0329 => "crypto_engine_test.rs",
        0x032A => "event_manager_test.rs",
        0x032B => "misc_manager_test.rs",
        0x032C => "request_manager_test.rs",
        0x032D => "storage_io_test.rs",
        0x032E => "time_keeper_test.rs",
        0x032F => "auth_token_test.rs",
        _ => "unknown",
    }
}


/// Must match MAX_LOG_TRACE_NUM_FFI in companion_device_auth_ffi.rs.
const MAX_ENTRIES: usize = crate::entry::companion_device_auth_ffi::MAX_LOG_TRACE_NUM_FFI;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LogTraceEntry {
    pub code: i32,
    pub file_id: u16,
    pub line_num: u16,
}

impl Default for LogTraceEntry {
    fn default() -> Self {
        Self {
            code: 0,
            file_id: 0,
            line_num: 0,
        }
    }
}

struct LogTraceState {
    enabled: bool,
    entries: [LogTraceEntry; MAX_ENTRIES],
    record_count: u32,
    write_index: u32,
}

const INIT_ENTRY: LogTraceEntry = LogTraceEntry {
    code: 0,
    file_id: 0,
    line_num: 0,
};

static mut STATE: LogTraceState = LogTraceState {
    enabled: false,
    entries: [INIT_ENTRY; MAX_ENTRIES],
    record_count: 0,
    write_index: 0,
};

/// Enable trace recording and clear previous entries.
pub fn enable() {
    unsafe {
        STATE.enabled = true;
        STATE.record_count = 0;
        STATE.write_index = 0;
    }
}

/// Disable trace recording and clear the buffer.
pub fn disable() {
    unsafe {
        STATE.enabled = false;
        STATE.record_count = 0;
        STATE.write_index = 0;
    }
}

/// Record a trace entry. Called from Logger::log implementations for ERROR level.
pub fn record(file_id: u16, line_num: u32) {
    unsafe {
        if !STATE.enabled {
            return;
        }
        let idx = STATE.write_index as usize;
        STATE.entries[idx] = LogTraceEntry {
            code: 0,
            file_id,
            line_num: line_num as u16,
        };
        STATE.write_index = (STATE.write_index + 1) % MAX_ENTRIES as u32;
        if STATE.record_count < MAX_ENTRIES as u32 {
            STATE.record_count += 1;
        }
    }
}

/// Export recorded entries to FFI array. Returns the number of entries exported.
pub fn export(
    entries: &mut [crate::entry::companion_device_auth_ffi::LogTraceEntryFfi],
) -> u32 {
    let (count, write_index) = unsafe { (STATE.record_count, STATE.write_index) };
    if entries.len() < MAX_ENTRIES || count as usize > entries.len() {
        return 0;
    }
    for i in 0..count as usize {
        let src_idx = if count < MAX_ENTRIES as u32 {
            i
        } else {
            (write_index as usize + i) % MAX_ENTRIES
        };
        let src = unsafe { STATE.entries[src_idx] };
        entries[i] = crate::entry::companion_device_auth_ffi::LogTraceEntryFfi {
            code: src.code,
            file_id: src.file_id,
            line_num: src.line_num,
        };
    }
    count
}
