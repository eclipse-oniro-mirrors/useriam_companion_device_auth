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

use crate::commands::system_commands::{
    companion_begin_add_host_binding, companion_begin_delegate_auth, companion_begin_obtain_token,
    companion_cancel_issue_token, companion_cancel_obtain_token, companion_end_add_host_binding,
    companion_end_delegate_auth, companion_end_obtain_token, companion_get_persisted_status,
    companion_init_key_negotiation, companion_pre_issue_token, companion_process_check, companion_process_issue_token,
    companion_process_token_auth, companion_remove_host_binding, companion_revoke_token, get_executor_info,
    host_begin_add_companion, host_begin_companion_check, host_begin_delegate_auth,
    host_begin_issue_token, host_begin_token_auth, host_cancel_add_companion, host_cancel_companion_check,
    host_cancel_delegate_auth, host_cancel_issue_token, host_cancel_obtain_token, host_check_template_enrolled,
    host_end_add_companion, host_end_companion_check, host_end_delegate_auth, host_end_issue_token,
    host_end_token_auth, host_get_init_key_negotiation, host_get_persisted_status, host_on_register_finish,
    host_pre_issue_token, host_process_obtain_token, host_process_pre_obtain_token, host_remove_companion,
    host_revoke_token, host_update_companion_enabled_business_ids, host_update_companion_status, host_update_token,
    init, set_active_user_id,
};
use crate::common::constants::ErrorCode;
use crate::ensure_or_return_val;
use crate::entry::companion_device_auth_ffi::CommandId::{
    CompanionBeginAddHostBinding, CompanionBeginDelegateAuth, CompanionBeginObtainToken, CompanionCancelIssueToken,
    CompanionCancelObtainToken, CompanionEndAddHostBinding, CompanionEndDelegateAuth, CompanionEndObtainToken,
    CompanionGetPersistedStatus, CompanionInitKeyNegotiation, CompanionPreIssueToken, CompanionProcessCheck,
    CompanionProcessIssueToken, CompanionProcessTokenAuth, CompanionRemoveHostBinding, CompanionRevokeToken,
    GetExecutorInfo, HostBeginAddCompanion, HostBeginCompanionCheck, HostBeginDelegateAuth,
    HostBeginIssueToken, HostBeginTokenAuth, HostCancelAddCompanion, HostCancelCompanionCheck, HostCancelDelegateAuth,
    HostCancelIssueToken, HostCancelObtainToken, HostCheckTemplateEnrolled, HostEndAddCompanion, HostEndCompanionCheck,
    HostEndDelegateAuth, HostEndIssueToken, HostEndTokenAuth, HostGetInitKeyNegotiation, HostGetPersistedStatus,
    HostPreIssueToken, HostProcessObtainToken, HostProcessPreObtainToken, HostRegisterFinish, HostRemoveCompanion,
    HostRevokeToken, HostUpdateCompanionEnabledBusinessIds, HostUpdateCompanionStatus, HostUpdateToken, Init,
    SetActiveUserId,
};
use crate::entry::companion_device_auth_ffi::{
    CommandId, CommonOutputFfi, DataArray256Ffi, DataArray64Ffi, EventFfi, RustCommandParam, MAX_EVENT_NUM_FFI,
};
use crate::impls::default_event_manager;
use crate::impls::default_misc_manager;
use crate::impls::default_storage_io;
use crate::impls::default_time_keeper;
use crate::impls::openssl_crypto_engine;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::event_manager::EventManagerRegistry;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::request_manager::RequestManagerRegistry;
use crate::traits::logger::LoggerRegistry;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::storage_io::StorageIoRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::BTreeMap;
use crate::Box;
use crate::Vec;
use crate::UUID_LEN;
use crate::{log_e, log_i, p};
use core::mem::size_of;
use core::slice;

struct CmdInfo {
    command_id: CommandId,
    handler: &'static dyn CmdHandler,
}

trait CmdHandler {
    fn handle(&self, input: &[u8], output: &mut [u8]) -> Result<(), ErrorCode>;
}

fn invoke_cmd_handle<T, R, F>(input: &[u8], output: &mut [u8], f: F) -> Result<(), ErrorCode>
where
    T: Default,
    R: Default,
    F: FnOnce(&T, &mut R) -> Result<(), ErrorCode>,
{
    if input.len() != size_of::<T>() {
        log_e!("input len is not match {}:{}", input.len(), size_of::<T>());
        return Err(ErrorCode::BadParam);
    }
    if output.len() != size_of::<R>() {
        log_e!("output len is not match {}:{}", output.len(), size_of::<R>());
        return Err(ErrorCode::BadParam);
    }

    let mut input_val = Box::<T>::default();
    let mut output_val = Box::<R>::default();

    unsafe {
        *input_val = input.as_ptr().cast::<T>().read_unaligned();
    }

    f(&input_val, &mut output_val)?;

    unsafe {
        output.as_mut_ptr().cast::<R>().write_unaligned(*output_val);
    }

    Ok(())
}

macro_rules! impl_cmd_trait {
    () => {};
    ($cmd: expr, $handle: path) => {
        (|| -> CmdInfo {
            struct Foo;
            impl CmdHandler for Foo {
                fn handle(&self, input: &[u8], output: &mut [u8]) -> Result<(), ErrorCode> {
                    invoke_cmd_handle(input, output, $handle)
                }
            }
            CmdInfo { command_id: $cmd, handler: &Foo }
        })()
    };
}

macro_rules! count_args {
    () => {
        0
    };
    ($([$($expr:expr),*]),*) => {
        [$(count_args!(@inner $($expr),*)),*].len()
    };
    (@inner $($expr:expr),*) => {
        ()
    };
}

macro_rules! register_cmd {
    ($([ $cmd: expr, $handle: path]),*) => {{
        struct OnceCell<T>(core::cell::OnceCell<T>);
        unsafe impl<T> Sync for OnceCell<T> {}
        static __ALL: OnceCell<[CmdInfo; count_args!($([$cmd]),*)]> = OnceCell(core::cell::OnceCell::new());
        __ALL.0.get_or_init(||
        [ $(impl_cmd_trait!($cmd, $handle)), *])
    }}
}

fn handle_rust_command_inner(command_id: i32, input: &[u8], output: &mut [u8]) -> Result<(), ErrorCode> {
    let infos = register_cmd![
        [Init, init],
        [GetExecutorInfo, get_executor_info],
        [SetActiveUserId, set_active_user_id],
        [HostRegisterFinish, host_on_register_finish],
        [HostGetPersistedStatus, host_get_persisted_status],
        [HostBeginCompanionCheck, host_begin_companion_check],
        [HostEndCompanionCheck, host_end_companion_check],
        [HostCancelCompanionCheck, host_cancel_companion_check],
        [HostGetInitKeyNegotiation, host_get_init_key_negotiation],
        [HostBeginAddCompanion, host_begin_add_companion],
        [HostEndAddCompanion, host_end_add_companion],
        [HostCancelAddCompanion, host_cancel_add_companion],
        [HostRemoveCompanion, host_remove_companion],
        [HostPreIssueToken, host_pre_issue_token],
        [HostBeginIssueToken, host_begin_issue_token],
        [HostEndIssueToken, host_end_issue_token],
        [HostCancelIssueToken, host_cancel_issue_token],
        [HostBeginTokenAuth, host_begin_token_auth],
        [HostEndTokenAuth, host_end_token_auth],
        [HostRevokeToken, host_revoke_token],
        [HostUpdateCompanionStatus, host_update_companion_status],
        [HostUpdateCompanionEnabledBusinessIds, host_update_companion_enabled_business_ids],
        [HostBeginDelegateAuth, host_begin_delegate_auth],
        [HostEndDelegateAuth, host_end_delegate_auth],
        [HostCancelDelegateAuth, host_cancel_delegate_auth],
        [HostProcessPreObtainToken, host_process_pre_obtain_token],
        [HostProcessObtainToken, host_process_obtain_token],
        [HostCancelObtainToken, host_cancel_obtain_token],
        [HostCheckTemplateEnrolled, host_check_template_enrolled],
        [HostUpdateToken, host_update_token],
        [CompanionGetPersistedStatus, companion_get_persisted_status],
        [CompanionProcessCheck, companion_process_check],
        [CompanionInitKeyNegotiation, companion_init_key_negotiation],
        [CompanionBeginAddHostBinding, companion_begin_add_host_binding],
        [CompanionEndAddHostBinding, companion_end_add_host_binding],
        [CompanionRemoveHostBinding, companion_remove_host_binding],
        [CompanionPreIssueToken, companion_pre_issue_token],
        [CompanionProcessIssueToken, companion_process_issue_token],
        [CompanionCancelIssueToken, companion_cancel_issue_token],
        [CompanionProcessTokenAuth, companion_process_token_auth],
        [CompanionRevokeToken, companion_revoke_token],
        [CompanionBeginDelegateAuth, companion_begin_delegate_auth],
        [CompanionEndDelegateAuth, companion_end_delegate_auth],
        [CompanionBeginObtainToken, companion_begin_obtain_token],
        [CompanionEndObtainToken, companion_end_obtain_token],
        [CompanionCancelObtainToken, companion_cancel_obtain_token]
    ];
    for info in infos {
        if info.command_id as i32 == command_id {
            return match info.handler.handle(input, output) {
                Ok(()) => Ok(()),
                Err(e) => {
                    log_e!("command {:?} handle error:{:?}", info.command_id, e);
                    Err(e)
                },
            };
        }
    }
    log_e!("command id {:?} not recognized", command_id);
    Err(ErrorCode::BadParam)
}

pub fn handle_rust_command(
    command_id: i32,
    input: &[u8],
    output: &mut [u8],
    common_output: &mut [u8],
) -> Result<(), ErrorCode> {
    ensure_or_return_val!(common_output.len() == size_of::<CommonOutputFfi>(), ErrorCode::BadParam);
    let result: ErrorCode;
    match handle_rust_command_inner(command_id, input, output) {
        Ok(()) => {
            log_i!("handle command id {:?} success", command_id);
            result = ErrorCode::Success;
        },
        Err(e) => {
            log_e!("handle command id {:?} error:{:?}", command_id, e);
            result = e;
        },
    }
    let mut common_output_ffi = CommonOutputFfi::default();
    common_output_ffi.result = result as i32;

    unsafe {
        core::ptr::write_unaligned(common_output.as_mut_ptr() as *mut CommonOutputFfi, common_output_ffi);
    }

    Ok(())
}

pub fn handle_rust_env_init() -> Result<(), ErrorCode> {
    crate::log_i!("init_rust_env begin");

    LoggerRegistry::set(Box::new(crate::impls::hilog_logger::HilogLogger::new()));
    StorageIoRegistry::set(Box::new(crate::impls::default_storage_io::DefaultStorageIo::new()));
    TimeKeeperRegistry::set(Box::new(crate::impls::default_time_keeper::DefaultTimeKeeper::new()));
    CryptoEngineRegistry::set(Box::new(crate::impls::openssl_crypto_engine::OpenSSLCryptoEngine::new()));

    EventManagerRegistry::set(Box::new(crate::impls::default_event_manager::DefaultEventManager::new()));
    MiscManagerRegistry::set(Box::new(crate::impls::default_misc_manager::DefaultMiscManager::new()));

    CompanionDbManagerRegistry::set(Box::new(
        crate::impls::default_companion_db_manager::DefaultCompaniomDbManager::new(),
    ));

    RequestManagerRegistry::set(Box::new(
        crate::impls::default_request_manager::DefaultRequestManager::new(),
    ));

    HostDbManagerRegistry::set(Box::new(crate::impls::default_host_db_manager::DefaultHostDbManager::new()));

    crate::log_i!("init_rust_env: all trait implementations registered successfully");
    Ok(())
}

pub fn handle_rust_env_uninit() -> Result<(), ErrorCode> {
    crate::log_i!("uninit_rust_env begin");

    LoggerRegistry::reset();
    StorageIoRegistry::reset();
    TimeKeeperRegistry::reset();
    CryptoEngineRegistry::reset();
    EventManagerRegistry::reset();
    MiscManagerRegistry::reset();
    CompanionDbManagerRegistry::reset();
    RequestManagerRegistry::reset();
    HostDbManagerRegistry::reset();

    crate::log_i!("uninit_rust_env end");
    Ok(())
}
