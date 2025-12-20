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

use crate::common::constants::*;
use crate::common::types::*;
use crate::commands::common_command::{companion_status_vec_to_ffi, host_binding_status_vec_to_ffi};
use crate::entry::companion_device_auth_ffi::CommandId;
use crate::entry::companion_device_auth_ffi::*;
use crate::jobs::companion_db_helper;
use crate::jobs::host_db_helper;
use crate::request::auth::companion_auth::{
    CompanionDelegateAuthRequest, CompanionTokenAuthRequest,
};
use crate::request::auth::host_auth::{HostDelegateAuthRequest, HostTokenAuthRequest};
use crate::request::enroll::companion_enroll::CompanionDeviceEnrollRequest;
use crate::request::enroll::host_enroll::HostDeviceEnrollRequest;
use crate::request::issue_token::companion_issue_token::CompanionDeviceIssueTokenRequest;
use crate::request::issue_token::host_issue_token::HostDeviceIssueTokenRequest;
use crate::request::obtain_token::companion_obtain_token::CompanionDeviceObtainTokenRequest;
use crate::request::obtain_token::host_obtain_token::HostDeviceObtainTokenRequest;
use crate::request::sync_status::companion_sync_status::CompanionDeviceSyncStatusRequest;
use crate::request::sync_status::host_sync_status::HostDeviceSyncStatusRequest;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::companion_request_manager::{
    CompanionRequest, CompanionRequestInput, CompanionRequestManagerRegistry,
    CompanionRequestOutput,
};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::HostDeviceInfo;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::host_request_manager::{
    HostRequest, HostRequestInput, HostRequestManagerRegistry, HostRequestOutput,
};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::{log_e, log_i, p, Box, Vec};
use core::convert::TryFrom;

static mut INIT_FLAG: bool = false;

// Init
pub fn init(_input: InitInputFfi, _output: &mut InitOutputFfi) -> Result<(), ErrorCode> {
    log_i!("init start");
    let key_pair = CryptoEngineRegistry::get()
        .generate_ed25519_key_pair()
        .map_err(|e| p!(e))?;
    MiscManagerRegistry::get_mut()
        .set_local_key_pair(key_pair)
        .map_err(|e| p!(e))?;

    CompanionDbManagerRegistry::get_mut()
        .read_device_db()
        .map_err(|e| p!(e))?;
    HostDbManagerRegistry::get_mut()
        .read_device_db()
        .map_err(|e| p!(e))?;
    Ok(())
}

// GetExecutorInfo
pub fn get_executor_info(
    _input: GetExecutorInfoInputFfi,
    output: &mut GetExecutorInfoOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("get_executor_info start");
    let key_pair = MiscManagerRegistry::get_mut()
        .get_local_key_pair()
        .map_err(|e| p!(e))?;

    output.esl = ExecutorSecurityLevel::Esl3 as i32;
    output.max_template_acl = AuthCapabilityLevel::Acl3 as i32;
    output.public_key = key_pair.pub_key.clone().try_into().map_err(|e| p!(e))?;
    Ok(())
}

// OnRegisterFinish
pub fn host_on_register_finish(
    input: HostRegisterFinishInputFfi,
    _output: &mut HostRegisterFinishOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_on_register_finish start");
    MiscManagerRegistry::get_mut()
        .set_fwk_pub_key(input.public_key.try_into().map_err(|e| p!(e))?)?;
    host_db_helper::verify_template(input.template_ids.try_into().map_err(|e| p!(e))?)?;
    Ok(())
}

// HostGetPersistedStatus
pub fn host_get_persisted_status(
    input: HostGetPersistedStatusInputFfi,
    output: &mut HostGetPersistedStatusOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_get_persisted_status start");
    let mut companion_status_list: Vec<PersistedCompanionStatusFfi> = Vec::new();
    match HostDbManagerRegistry::get_mut().get_device_list(input.user_id) {
        Ok(device_list) => {
            for device_info in device_list {
                let device_base_info = HostDbManagerRegistry::get_mut()
                    .read_device_base_info(device_info.template_id)?;

                let companion_status = PersistedCompanionStatusFfi {
                    template_id: device_info.template_id,
                    host_user_id: device_info.user_info.user_id,
                    companion_device_key: DeviceKeyFfi::try_from(device_info.device_key)?,
                    is_valid: device_info.is_valid as u8,
                    enabled_business_ids: Int32Array64Ffi::try_from(device_base_info.business_ids)?,
                    added_time: device_info.added_time,
                    secure_protocol_id: device_info.secure_protocol_id,
                    device_model: DataArray256Ffi::try_from(device_base_info.device_model)?,
                    device_user_name: DataArray256Ffi::try_from(device_base_info.device_user_name)?,
                    device_name: DataArray256Ffi::try_from(device_base_info.device_name)?,
                };

                companion_status_list.push(companion_status);
            }
            companion_status_vec_to_ffi(companion_status_list, &mut output.companion_status_list)?;
            Ok(())
        }
        Err(ErrorCode::NotFound) => {
            log_i!("No devices found for user {}", input.user_id);
            companion_status_vec_to_ffi(companion_status_list, &mut output.companion_status_list)?;
            Ok(())
        }
        Err(e) => {
            log_e!("Error getting device list: {:?}", e);
            Err(e)
        }
    }
}

// HostBeginCompanionCheck
pub fn host_begin_companion_check(
    input: HostBeginCompanionCheckInputFfi,
    output: &mut HostBeginCompanionCheckOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_begin_companion_check start");
    let mut sync_status_request = HostDeviceSyncStatusRequest::new(&input)?;
    let sync_status_input = HostRequestInput::SyncStatusBegin(input);
    let result = sync_status_request.begin(sync_status_input)?;
    let HostRequestOutput::SyncStatusBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    HostRequestManagerRegistry::get_mut().add_request(Box::new(sync_status_request))?;
    *output = output_ffi;
    Ok(())
}

// HostEndCompanionCheck
pub fn host_end_companion_check(
    input: HostEndCompanionCheckInputFfi,
    output: &mut HostEndCompanionCheckOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_end_companion_check start");
    let mut sync_status_request =
        HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let sync_status_input = HostRequestInput::SyncStatusEnd(input);
    let result = sync_status_request.end(sync_status_input)?;
    let HostRequestOutput::SyncStatusEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// HostCancelCompanionCheck
pub fn host_cancel_companion_check(
    input: HostCancelCompanionCheckInputFfi,
    _output: &mut HostCancelCompanionCheckOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_cancel_companion_check start");
    HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// HostGetInitKeyNegotiation
pub fn host_get_init_key_negotiation(
    input: HostGetInitKeyNegotiationInputFfi,
    output: &mut HostGetInitKeyNegotiationOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_get_init_key_negotiation start");
    let mut enroll_request = HostDeviceEnrollRequest::new(&input)?;
    let key_nego_input = HostRequestInput::KeyNego(input);
    let result = enroll_request.prepare(key_nego_input)?;
    let HostRequestOutput::KeyNego(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    HostRequestManagerRegistry::get_mut().add_request(Box::new(enroll_request))?;
    *output = output_ffi;
    Ok(())
}

// HostBeginAddCompanion
pub fn host_begin_add_companion(
    input: HostBeginAddCompanionInputFfi,
    output: &mut HostBeginAddCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_begin_add_companion start");
    let enroll_request = HostRequestManagerRegistry::get_mut().get_request(input.request_id)?;
    let enroll_input = HostRequestInput::EnrollBegin(input);
    let result = enroll_request.begin(enroll_input)?;
    let HostRequestOutput::EnrollBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// HostEndAddCompanion
pub fn host_end_add_companion(
    input: HostEndAddCompanionInputFfi,
    output: &mut HostEndAddCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_end_add_companion start");
    let mut enroll_request =
        HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let enroll_input = HostRequestInput::EnrollEnd(input);
    let result = enroll_request.end(enroll_input)?;
    let HostRequestOutput::EnrollEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// HostCancelAddCompanion
pub fn host_cancel_add_companion(
    input: HostCancelAddCompanionInputFfi,
    output: &mut HostCancelAddCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_cancel_add_companion start");
    HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// HostRemoveCompanion
pub fn host_remove_companion(
    input: HostRemoveCompanionInputFfi,
    output: &mut HostRemoveCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_remove_companion start");
    let device_info = host_db_helper::get_companion_device(input.template_id)?;
    let user_id = device_info.user_info.user_id;
    let companion_device_key = DeviceKeyFfi::try_from(device_info.device_key)?;
    host_db_helper::delete_companion_device(input.template_id)?;
    output.user_id = user_id;
    output.companion_device_key = companion_device_key;
    Ok(())
}

// HostPreIssueToken
pub fn host_pre_issue_token(
    input: HostPreIssueTokenInputFfi,
    output: &mut HostPreIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_pre_issue_token start");
    let mut issue_token_request = HostDeviceIssueTokenRequest::new(&input)?;
    let issue_token_input = HostRequestInput::IssueTokenPrepare(input);
    let result = issue_token_request.prepare(issue_token_input)?;
    let HostRequestOutput::IssueTokenPrepare(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    HostRequestManagerRegistry::get_mut().add_request(Box::new(issue_token_request))?;
    *output = output_ffi;
    Ok(())
}

// HostBeginIssueToken
pub fn host_begin_issue_token(
    input: HostBeginIssueTokenInputFfi,
    output: &mut HostBeginIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_begin_issue_token start");
    let issue_token_request: &mut dyn HostRequest =
        HostRequestManagerRegistry::get_mut().get_request(input.request_id)?;
    let issue_token_input = HostRequestInput::IssueTokenBegin(input);
    let result = issue_token_request.begin(issue_token_input)?;
    let HostRequestOutput::IssueTokenBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// HostEndIssueToken
pub fn host_end_issue_token(
    input: HostEndIssueTokenInputFfi,
    output: &mut HostEndIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_end_issue_token start");
    let mut issue_token_request =
        HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let issue_token_input = HostRequestInput::IssueTokenEnd(input);
    let result = issue_token_request.end(issue_token_input)?;
    let HostRequestOutput::IssueTokenEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// HostCancelIssueToken
pub fn host_cancel_issue_token(
    input: HostCancelIssueTokenInputFfi,
    output: &mut HostCancelIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_cancel_issue_token start");
    HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// HostBeginTokenAuth
pub fn host_begin_token_auth(
    input: HostBeginTokenAuthInputFfi,
    output: &mut HostBeginTokenAuthOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_begin_token_auth start");
    let mut token_auth_request = HostTokenAuthRequest::new(&input)?;
    let auth_input = HostRequestInput::TokenAuthBegin(input);
    let result = token_auth_request.begin(auth_input)?;
    let HostRequestOutput::TokenAuthBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    HostRequestManagerRegistry::get_mut().add_request(Box::new(token_auth_request))?;
    *output = output_ffi;
    Ok(())
}

// HostEndTokenAuth
pub fn host_end_token_auth(
    input: HostEndTokenAuthInputFfi,
    output: &mut HostEndTokenAuthOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_end_token_auth start");
    let mut token_auth_request =
        HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let auth_input = HostRequestInput::TokenAuthEnd(input);
    let result = token_auth_request.end(auth_input)?;
    let HostRequestOutput::TokenAuthEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// HostRevokeToken
pub fn host_revoke_token(
    input: HostRevokeTokenInputFfi,
    output: &mut HostRevokeTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_revoke_token start");
    host_db_helper::delete_companion_device_token(input.template_id)?;
    Ok(())
}

// HostUpdateCompanionStatus
pub fn host_update_companion_status(
    input: HostUpdateCompanionStatusInputFfi,
    output: &mut HostUpdateCompanionStatusOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_update_companion_status start");
    host_db_helper::update_companion_device_info(
        input.template_id,
        input.device_name.to_string()?,
        input.device_user_name.to_string()?,
    )?;
    return Err(ErrorCode::GeneralError);
}

// HostUpdateCompanionEnabledBusinessIds
pub fn host_update_companion_enabled_business_ids(
    input: HostUpdateCompanionEnabledBusinessIdsInputFfi,
    output: &mut HostUpdateCompanionEnabledBusinessIdsOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_update_companion_enabled_business_ids start");
    host_db_helper::update_device_business_id(
        input.template_id,
        Vec::<i32>::try_from(input.business_ids).map_err(|e| p!(e))?,
    )?;
    Ok(())
}

// HostBeginDelegateAuth
pub fn host_begin_delegate_auth(
    input: HostBeginDelegateAuthInputFfi,
    output: &mut HostBeginDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_begin_delegate_auth start");
    let mut delegate_auth_request = HostDelegateAuthRequest::new(&input)?;
    let auth_input = HostRequestInput::DelegateAuthBegin(input);
    let result = delegate_auth_request.begin(auth_input)?;
    let HostRequestOutput::DelegateAuthBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    HostRequestManagerRegistry::get_mut().add_request(Box::new(delegate_auth_request))?;
    *output = output_ffi;
    Ok(())
}

// HostEndDelegateAuth
pub fn host_end_delegate_auth(
    input: HostEndDelegateAuthInputFfi,
    output: &mut HostEndDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_end_delegate_auth start");
    let mut delegate_auth_request =
        HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let auth_input = HostRequestInput::DelegateAuthEnd(input);
    let result = delegate_auth_request.end(auth_input)?;
    let HostRequestOutput::DelegateAuthEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// HostCancelDelegateAuth
pub fn host_cancel_delegate_auth(
    input: HostCancelDelegateAuthInputFfi,
    output: &mut HostCancelDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_cancel_delegate_auth start");
    HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// HostProcessPreObtainToken
pub fn host_process_pre_obtain_token(
    input: HostProcessPreObtainTokenInputFfi,
    output: &mut HostProcessPreObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_process_pre_obtain_token start");
    let mut obtain_token_request = HostDeviceObtainTokenRequest::new(&input)?;
    let obtain_token_input = HostRequestInput::ObtainTokenBegin(input);
    let result = obtain_token_request.begin(obtain_token_input)?;
    let HostRequestOutput::ObtainTokenBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    HostRequestManagerRegistry::get_mut().add_request(Box::new(obtain_token_request))?;
    *output = output_ffi;
    Ok(())
}

// HostProcessObtainToken
pub fn host_process_obtain_token(
    input: HostProcessObtainTokenInputFfi,
    output: &mut HostProcessObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_process_obtain_token start");
    let mut obtain_token_request =
        HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let obtain_token_input = HostRequestInput::ObtainTokenEnd(input);
    let result = obtain_token_request.end(obtain_token_input)?;
    let HostRequestOutput::ObtainTokenEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// HostCancelObtainToken
pub fn host_cancel_obtain_token(
    input: HostCancelObtainTokenInputFfi,
    output: &mut HostCancelObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("host_cancel_obtain_token start");
    HostRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// CompanionGetPersistedStatus
pub fn companion_get_persisted_status(
    input: CompanionGetPersistedStatusInputFfi,
    output: &mut CompanionGetPersistedStatusOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_get_persisted_status start");
    let mut binding_status_list: Vec<PersistedHostBindingStatusFfi> = Vec::new();
    match CompanionDbManagerRegistry::get_mut().get_device_list(input.user_id) {
        Ok(device_list) => {
            for device_info in device_list {
                let binding_status = PersistedHostBindingStatusFfi {
                    binding_id: device_info.binding_id,
                    companion_user_id: device_info.user_info.user_id,
                    host_device_key: DeviceKeyFfi::try_from(device_info.device_key)?,
                    is_token_valid: device_info.is_token_valid,
                };
                binding_status_list.push(binding_status);
            }
            host_binding_status_vec_to_ffi(binding_status_list, &mut output.binding_status_list)?;
            Ok(())
        }
        Err(ErrorCode::NotFound) => {
            log_i!("No devices found for user {}", input.user_id);
            host_binding_status_vec_to_ffi(binding_status_list, &mut output.binding_status_list)?;
            Ok(())
        }
        Err(e) => {
            log_e!("Error getting device list: {:?}", e);
            Err(e)
        }
    }
}

// CompanionProcessCheck
pub fn companion_process_check(
    input: CompanionProcessCheckInputFfi,
    output: &mut CompanionProcessCheckOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_process_check start");
    let mut sync_status_request = CompanionDeviceSyncStatusRequest::new(&input)?;
    let sync_status_input = CompanionRequestInput::SyncStatus(input);
    let result = sync_status_request.begin(sync_status_input)?;
    let CompanionRequestOutput::SyncStatus(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// CompanionInitKeyNegotiation
pub fn companion_init_key_negotiation(
    input: CompanionInitKeyNegotiationInputFfi,
    output: &mut CompanionInitKeyNegotiationOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_init_key_negotiation start");
    let mut enroll_request = CompanionDeviceEnrollRequest::new(&input)?;
    let key_nego_input = CompanionRequestInput::KeyNego(input);
    let result = enroll_request.prepare(key_nego_input)?;
    let CompanionRequestOutput::KeyNego(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    CompanionRequestManagerRegistry::get_mut().add_request(Box::new(enroll_request))?;
    *output = output_ffi;
    Ok(())
}

// CompanionBeginAddHostBinding
pub fn companion_begin_add_host_binding(
    input: CompanionBeginAddHostBindingInputFfi,
    output: &mut CompanionBeginAddHostBindingOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_begin_add_host_binding start");
    let enroll_request =
        CompanionRequestManagerRegistry::get_mut().get_request(input.request_id)?;
    let enroll_input = CompanionRequestInput::EnrollBegin(input);
    let result = enroll_request.begin(enroll_input)?;
    let CompanionRequestOutput::EnrollBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// CompanionEndAddHostBinding
pub fn companion_end_add_host_binding(
    input: CompanionEndAddHostBindingInputFfi,
    output: &mut CompanionEndAddHostBindingOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_end_add_host_binding start");
    let mut enroll_request =
        CompanionRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let enroll_input = CompanionRequestInput::EnrollEnd(input);
    let result = enroll_request.end(enroll_input)?;
    let CompanionRequestOutput::EnrollEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// CompanionRemoveHostBinding
pub fn companion_remove_host_binding(
    input: CompanionRemoveHostBindingInputFfi,
    output: &mut CompanionRemoveHostBindingOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_remove_host_binding start");
    companion_db_helper::delete_host_device(input.binding_id)?;
    Ok(())
}

// CompanionPreIssueToken
pub fn companion_pre_issue_token(
    input: CompanionPreIssueTokenInputFfi,
    output: &mut CompanionPreIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_pre_issue_token start");
    let mut issue_token_request = CompanionDeviceIssueTokenRequest::new(&input)?;
    let issue_token_input = CompanionRequestInput::IssueTokenBegin(input);
    let result = issue_token_request.begin(issue_token_input)?;
    let CompanionRequestOutput::IssueTokenBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    CompanionRequestManagerRegistry::get_mut().add_request(Box::new(issue_token_request))?;
    *output = output_ffi;
    Ok(())
}

// CompanionProcessIssueToken
pub fn companion_process_issue_token(
    input: CompanionProcessIssueTokenInputFfi,
    output: &mut CompanionProcessIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_process_issue_token start");
    let mut issue_token_request =
        CompanionRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let issue_token_input = CompanionRequestInput::IssueTokenEnd(input);
    let result = issue_token_request.end(issue_token_input)?;
    let CompanionRequestOutput::IssueTokenEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// CompanionCancelIssueToken
pub fn companion_cancel_issue_token(
    input: CompanionCancelIssueTokenInputFfi,
    output: &mut CompanionCancelIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_cancel_issue_token start");
    CompanionRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// CompanionProcessTokenAuth
pub fn companion_process_token_auth(
    input: CompanionProcessTokenAuthInputFfi,
    output: &mut CompanionProcessTokenAuthOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_process_token_auth start");
    let mut token_auth_request = CompanionTokenAuthRequest::new(&input)?;
    let auth_input = CompanionRequestInput::TokenAuthBegin(input);
    let result = token_auth_request.begin(auth_input)?;
    let CompanionRequestOutput::TokenAuthBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    CompanionRequestManagerRegistry::get_mut().add_request(Box::new(token_auth_request))?;
    *output = output_ffi;
    Ok(())
}

// CompanionRevokeToken
pub fn companion_revoke_token(
    input: CompanionRevokeTokenInputFfi,
    output: &mut CompanionRevokeTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_revoke_token start");
    CompanionDbManagerRegistry::get_mut().delete_token_db(input.binding_id)?;
    Ok(())
}

// CompanionBeginDelegateAuth
pub fn companion_begin_delegate_auth(
    input: CompanionBeginDelegateAuthInputFfi,
    output: &mut CompanionBeginDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_begin_delegate_auth start");
    let mut delagate_auth_request = CompanionDelegateAuthRequest::new(&input)?;
    let auth_input = CompanionRequestInput::DelegateAuthBegin(input);
    let result = delagate_auth_request.begin(auth_input)?;
    let CompanionRequestOutput::DelegateAuthBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    CompanionRequestManagerRegistry::get_mut().add_request(Box::new(delagate_auth_request))?;
    *output = output_ffi;
    Ok(())
}

// CompanionEndDelegateAuth
pub fn companion_end_delegate_auth(
    input: CompanionEndDelegateAuthInputFfi,
    output: &mut CompanionEndDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_end_delegate_auth start");
    let mut delagate_auth_request =
        CompanionRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let auth_input = CompanionRequestInput::DelegateAuthEnd(input);
    let result = delagate_auth_request.end(auth_input)?;
    let CompanionRequestOutput::DelegateAuthEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };

    *output = output_ffi;
    Ok(())
}

// CompanionBeginObtainToken
pub fn companion_begin_obtain_token(
    input: CompanionBeginObtainTokenInputFfi,
    output: &mut CompanionBeginObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_begin_obtain_token start");
    let mut obtain_token_request = CompanionDeviceObtainTokenRequest::new(&input)?;
    let obtain_token_input = CompanionRequestInput::ObtainTokenBegin(input);
    let result = obtain_token_request.begin(obtain_token_input)?;
    let CompanionRequestOutput::ObtainTokenBegin(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    CompanionRequestManagerRegistry::get_mut().add_request(Box::new(obtain_token_request))?;
    *output = output_ffi;
    Ok(())
}

// CompanionEndObtainToken
pub fn companion_end_obtain_token(
    input: CompanionEndObtainTokenInputFfi,
    output: &mut CompanionEndObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_end_obtain_token start");
    let mut obtain_token_request =
        CompanionRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let obtain_token_input = CompanionRequestInput::ObtainTokenEnd(input);
    let result = obtain_token_request.end(obtain_token_input)?;
    let CompanionRequestOutput::ObtainTokenEnd(output_ffi) = result else {
        return Err(ErrorCode::GeneralError);
    };
    *output = output_ffi;
    Ok(())
}

// CompanionCancelObtainToken
pub fn companion_cancel_obtain_token(
    input: CompanionCancelObtainTokenInputFfi,
    output: &mut CompanionCancelObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    log_i!("companion_cancel_obtain_token start");
    CompanionRequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}
