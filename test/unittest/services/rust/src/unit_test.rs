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

// Commands
mod common_command_test;
mod system_commands_test;

// common
mod constants_test;
mod types_test;

// entry
mod companion_device_auth_entry_test;
mod companion_device_auth_ffi_test;

// impls
mod default_companion_db_manager_test;
mod default_companion_request_manager_test;
mod default_event_manager_test;
mod default_host_db_manager_test;
mod default_host_request_manager_test;
mod default_misc_manager_test;
mod default_storage_io_test;
mod default_time_keeper_test;
mod openssl_crypto_engine_test;

// jobs
mod companion_db_helper_test;
mod host_db_helper_test;
mod message_crypto_test;

// Request
// delegate_auth
mod companion_delegate_auth_test;
mod delegate_auth_message_test;
mod host_delegate_auth_test;

// enroll
mod companion_enroll_test;
mod enroll_message_test;
mod host_enroll_test;

// jobs
mod common_message_test;

// status_sync
mod companion_sync_status_test;
mod host_sync_status_test;

// token_auth
mod companion_token_auth_test;
mod host_token_auth_test;
mod token_auth_message_test;

// token_issue
mod companion_issue_token_test;
mod host_issue_token_test;
mod token_issue_message_test;

// token_obtain
mod companion_obtain_token_test;
mod host_obtain_token_test;
mod token_obtain_message_test;

// traits
mod companion_db_manager_test;
mod companion_request_manager_test;
mod crypto_engine_test;
mod event_manager_test;
mod host_db_manager_test;
mod host_request_manager_test;
mod misc_manager_test;
mod storage_io_test;
mod time_keeper_test;

// utils
mod attribute_test;
mod auth_token_test;
mod message_codec_test;
mod parcel_test;
mod scope_guard_test;
