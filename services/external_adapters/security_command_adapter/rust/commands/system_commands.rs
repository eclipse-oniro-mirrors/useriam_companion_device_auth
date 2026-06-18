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

use crate::commands::common_command::{companion_status_vec_to_ffi, host_binding_status_vec_to_ffi};
use crate::common::constants::{
    AuthCapabilityLevel, AuthTrustLevel, Capability, ErrorCode, ExecutorSecurityLevel, TOKEN_REFRESH_THRESHOLD,
    TOKEN_VALID_PERIOD,
};
use crate::entry::companion_device_auth_ffi::{
    CompanionBeginAddHostBindingInputFfi, CompanionBeginAddHostBindingOutputFfi, CompanionBeginDelegateAuthInputFfi,
    CompanionBeginDelegateAuthOutputFfi, CompanionBeginObtainTokenInputFfi, CompanionBeginObtainTokenOutputFfi,
    CompanionCancelIssueTokenInputFfi, CompanionCancelIssueTokenOutputFfi, CompanionCancelObtainTokenInputFfi,
    CompanionCancelObtainTokenOutputFfi, CompanionEndAddHostBindingInputFfi, CompanionEndAddHostBindingOutputFfi,
    CompanionEndDelegateAuthInputFfi, CompanionEndDelegateAuthOutputFfi, CompanionEndObtainTokenInputFfi,
    CompanionEndObtainTokenOutputFfi, CompanionGetPersistedStatusInputFfi, CompanionGetPersistedStatusOutputFfi,
    CompanionInitKeyNegotiationInputFfi, CompanionInitKeyNegotiationOutputFfi, CompanionPreIssueTokenInputFfi,
    CompanionPreIssueTokenOutputFfi, CompanionProcessCheckInputFfi, CompanionProcessCheckOutputFfi,
    CompanionProcessIssueTokenInputFfi, CompanionProcessIssueTokenOutputFfi, CompanionProcessTokenAuthInputFfi,
    CompanionProcessTokenAuthOutputFfi, CompanionRemoveHostBindingInputFfi, CompanionRemoveHostBindingOutputFfi,
    CompanionRevokeTokenInputFfi, CompanionRevokeTokenOutputFfi, DataArray1024Ffi, DataArray256Ffi, DeviceKeyFfi,
    GetExecutorInfoInputFfi, GetExecutorInfoOutputFfi, HostBeginAddCompanionInputFfi, HostBeginAddCompanionOutputFfi,
    HostBeginCompanionCheckInputFfi, HostBeginCompanionCheckOutputFfi, HostBeginDelegateAuthInputFfi,
    HostBeginDelegateAuthOutputFfi, HostBeginIssueTokenInputFfi, HostBeginIssueTokenOutputFfi,
    HostBeginTokenAuthInputFfi, HostBeginTokenAuthOutputFfi, HostCancelAddCompanionInputFfi,
    HostCancelAddCompanionOutputFfi, HostCancelCompanionCheckInputFfi, HostCancelCompanionCheckOutputFfi,
    HostCancelDelegateAuthInputFfi, HostCancelDelegateAuthOutputFfi, HostCancelIssueTokenInputFfi,
    HostCancelIssueTokenOutputFfi, HostCancelObtainTokenInputFfi, HostCancelObtainTokenOutputFfi,
    HostCheckTemplateEnrolledInputFfi, HostCheckTemplateEnrolledOutputFfi, HostEndAddCompanionInputFfi,
    HostEndAddCompanionOutputFfi, HostEndCompanionCheckInputFfi, HostEndCompanionCheckOutputFfi,
    HostEndDelegateAuthInputFfi, HostEndDelegateAuthOutputFfi, HostEndIssueTokenInputFfi, HostEndIssueTokenOutputFfi,
    HostEndTokenAuthInputFfi, HostEndTokenAuthOutputFfi, HostGetInitKeyNegotiationInputFfi,
    HostGetInitKeyNegotiationOutputFfi, HostGetPersistedStatusInputFfi, HostGetPersistedStatusOutputFfi,
    HostPreIssueTokenInputFfi, HostPreIssueTokenOutputFfi, HostProcessObtainTokenInputFfi,
    HostProcessObtainTokenOutputFfi, HostProcessPreObtainTokenInputFfi, HostProcessPreObtainTokenOutputFfi,
    HostRegisterFinishInputFfi, HostRegisterFinishOutputFfi, HostRemoveCompanionInputFfi, HostRemoveCompanionOutputFfi,
    HostRevokeTokenInputFfi, HostRevokeTokenOutputFfi, HostSetCompanionInvalidInputFfi,
    HostSetCompanionInvalidOutputFfi,
    HostUpdateCompanionEnabledBusinessIdsInputFfi,
    HostUpdateCompanionEnabledBusinessIdsOutputFfi, HostUpdateCompanionStatusInputFfi,
    HostUpdateCompanionStatusOutputFfi, HostRefreshTokenInputFfi, HostRefreshTokenOutputFfi, InitInputFfi,
    InitOutputFfi,
    Int32Array64Ffi, PersistedCompanionStatusFfi, PersistedHostBindingStatusFfi, SetActiveUserInputFfi,
    SetActiveUserOutputFfi,
};
use crate::jobs::companion_device_db_helper;
use crate::request::jobs::fwk_msg_validator;
use crate::request::delegate_auth::companion_delegate_auth::CompanionDelegateAuthRequest;
use crate::request::delegate_auth::host_delegate_auth::HostDelegateAuthRequest;
use crate::request::enroll::companion_enroll::CompanionDeviceEnrollRequest;
use crate::request::enroll::host_enroll::HostDeviceEnrollRequest;
use crate::request::status_sync::companion_sync_status::CompanionDeviceSyncStatusRequest;
use crate::request::status_sync::host_sync_status::HostDeviceSyncStatusRequest;
use crate::request::token_auth::companion_token_auth::CompanionTokenAuthRequest;
use crate::request::token_auth::host_token_auth::HostTokenAuthRequest;
use crate::request::token_issue::companion_issue_token::CompanionDeviceIssueTokenRequest;
use crate::request::token_issue::host_issue_token::HostDeviceIssueTokenRequest;
use crate::request::token_obtain::companion_obtain_token::CompanionDeviceObtainTokenRequest;
use crate::request::token_obtain::host_obtain_token::HostDeviceObtainTokenRequest;
use crate::traits::companion_device_db_manager::CompanionDeviceDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::host_binding_db_manager::HostBindingDbManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::request_manager::{Request, RequestManagerRegistry, RequestParam};
use crate::{log_e, log_i, p, Box, Vec};
use core::convert::TryFrom;
use crate::traits::log_trace::RustFileId;
pub(crate) const FILE_ID: u16 = RustFileId::SystemCommands as u16;

// Init
pub fn init(_input: &InitInputFfi, _output: &mut InitOutputFfi) -> Result<(), ErrorCode> {
    let key_pair = CryptoEngineRegistry::get().generate_ed25519_key_pair().map_err(|e| p!(e))?;
    MiscManagerRegistry::get_mut().set_local_key_pair(key_pair).map_err(|e| p!(e))?;

    HostBindingDbManagerRegistry::get_mut().read_device_db().map_err(|e| p!(e))?;
    CompanionDeviceDbManagerRegistry::get_mut().read_device_db().map_err(|e| p!(e))?;
    Ok(())
}

// GetExecutorInfo
pub fn get_executor_info(
    _input: &GetExecutorInfoInputFfi,
    output: &mut GetExecutorInfoOutputFfi,
) -> Result<(), ErrorCode> {
    let key_pair = MiscManagerRegistry::get_mut().get_local_key_pair().map_err(|e| p!(e))?;

    output.esl = ExecutorSecurityLevel::Esl3 as i32;
    output.max_template_acl = AuthCapabilityLevel::Acl3 as i32;
    output.public_key = key_pair.pub_key.clone().try_into().map_err(|e| p!(e))?;
    Ok(())
}

// SetActiveUserId
pub fn set_active_user_id(
    _input: &SetActiveUserInputFfi,
    _output: &mut SetActiveUserOutputFfi,
) -> Result<(), ErrorCode> {
    Ok(())
}

// OnRegisterFinish
pub fn host_on_register_finish(
    input: &HostRegisterFinishInputFfi,
    _output: &mut HostRegisterFinishOutputFfi,
) -> Result<(), ErrorCode> {
    MiscManagerRegistry::get_mut().set_fwk_pub_key(input.public_key.to_vec()?)?;
    companion_device_db_helper::verify_template(input.template_ids.try_into().map_err(|e| p!(e))?)?;
    Ok(())
}

// HostGetPersistedStatus
pub fn host_get_persisted_status(
    input: &HostGetPersistedStatusInputFfi,
    output: &mut HostGetPersistedStatusOutputFfi,
) -> Result<(), ErrorCode> {
    let mut companion_status_list: Vec<PersistedCompanionStatusFfi> = Vec::new();
    match companion_device_db_helper::get_companion_device_by_user_id(input.user_id) {
        Ok(device_list) => {
            for device_info in device_list {
                let device_profile =
                    CompanionDeviceDbManagerRegistry::get_mut().read_device_profile(device_info.template_id)?;

                let companion_status = PersistedCompanionStatusFfi {
                    template_id: device_info.template_id,
                    host_user_id: device_info.user_info.user_id,
                    companion_device_key: DeviceKeyFfi::try_from(device_info.device_key)?,
                    device_type: device_profile.device_type,
                    is_valid: device_info.is_valid as u8,
                    enabled_business_ids: Int32Array64Ffi::try_from(device_profile.business_ids)?,
                    added_time: device_info.added_time,
                    device_model_info: DataArray1024Ffi::try_from(device_profile.device_model_info)?,
                    device_user_name: DataArray256Ffi::try_from(device_profile.device_user_name)?,
                    device_name: DataArray256Ffi::try_from(device_profile.device_name)?,
                };

                companion_status_list.push(companion_status);
            }
            companion_status_vec_to_ffi(companion_status_list, &mut output.companion_status_list)?;
            Ok(())
        },
        Err(ErrorCode::NotFound) => {
            log_i!("No devices found for user {}", input.user_id);
            companion_status_vec_to_ffi(companion_status_list, &mut output.companion_status_list)?;
            Ok(())
        },
        Err(e) => {
            log_e!("Error getting device list: {:?}", e);
            Err(e)
        },
    }
}

// HostBeginCompanionCheck
pub fn host_begin_companion_check(
    input: &HostBeginCompanionCheckInputFfi,
    output: &mut HostBeginCompanionCheckOutputFfi,
) -> Result<(), ErrorCode> {
    let mut sync_status_request = HostDeviceSyncStatusRequest::new(input)?;
    sync_status_request.begin(RequestParam::HostSyncStatusBegin(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(sync_status_request))?;
    Ok(())
}

// HostEndCompanionCheck
pub fn host_end_companion_check(
    input: &HostEndCompanionCheckInputFfi,
    output: &mut HostEndCompanionCheckOutputFfi,
) -> Result<(), ErrorCode> {
    let mut sync_status_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    sync_status_request.end(RequestParam::HostSyncStatusEnd(input, output))?;
    Ok(())
}

// HostCancelCompanionCheck
pub fn host_cancel_companion_check(
    input: &HostCancelCompanionCheckInputFfi,
    _output: &mut HostCancelCompanionCheckOutputFfi,
) -> Result<(), ErrorCode> {
    RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// HostGetInitKeyNegotiation
pub fn host_get_init_key_negotiation(
    input: &HostGetInitKeyNegotiationInputFfi,
    output: &mut HostGetInitKeyNegotiationOutputFfi,
) -> Result<(), ErrorCode> {
    let mut enroll_request = HostDeviceEnrollRequest::new(input)?;
    enroll_request.prepare(RequestParam::HostKeyNego(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(enroll_request))?;
    Ok(())
}

// HostBeginAddCompanion
pub fn host_begin_add_companion(
    input: &HostBeginAddCompanionInputFfi,
    output: &mut HostBeginAddCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    let enroll_request = RequestManagerRegistry::get_mut().get_request(input.request_id)?;
    enroll_request.begin(RequestParam::HostEnrollBegin(input, output))?;
    Ok(())
}

// HostEndAddCompanion
pub fn host_end_add_companion(
    input: &HostEndAddCompanionInputFfi,
    output: &mut HostEndAddCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    let mut enroll_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    enroll_request.end(RequestParam::HostEnrollEnd(input, output))?;
    Ok(())
}

// HostCancelAddCompanion
pub fn host_cancel_add_companion(
    input: &HostCancelAddCompanionInputFfi,
    _output: &mut HostCancelAddCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// HostRemoveCompanion
pub fn host_remove_companion(
    input: &HostRemoveCompanionInputFfi,
    output: &mut HostRemoveCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    let device_info = CompanionDeviceDbManagerRegistry::get().get_device(input.template_id)?;
    let user_id = device_info.user_info.user_id;
    let companion_device_key = DeviceKeyFfi::try_from(device_info.device_key)?;
    CompanionDeviceDbManagerRegistry::get_mut().remove_device(input.template_id)?;
    output.user_id = user_id;
    output.companion_device_key = companion_device_key;
    Ok(())
}

// HostPreIssueToken
pub fn host_pre_issue_token(
    input: &HostPreIssueTokenInputFfi,
    output: &mut HostPreIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut issue_token_request = HostDeviceIssueTokenRequest::new(input)?;
    issue_token_request.prepare(RequestParam::HostIssueTokenPrepare(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(issue_token_request))?;
    Ok(())
}

// HostBeginIssueToken
pub fn host_begin_issue_token(
    input: &HostBeginIssueTokenInputFfi,
    output: &mut HostBeginIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let issue_token_request: &mut dyn Request = RequestManagerRegistry::get_mut().get_request(input.request_id)?;
    issue_token_request.begin(RequestParam::HostIssueTokenBegin(input, output))?;
    Ok(())
}

// HostEndIssueToken
pub fn host_end_issue_token(
    input: &HostEndIssueTokenInputFfi,
    output: &mut HostEndIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut issue_token_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    issue_token_request.end(RequestParam::HostIssueTokenEnd(input, output))?;
    Ok(())
}

// HostCancelIssueToken
pub fn host_cancel_issue_token(
    input: &HostCancelIssueTokenInputFfi,
    _output: &mut HostCancelIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// HostBeginTokenAuth
pub fn host_begin_token_auth(
    input: &HostBeginTokenAuthInputFfi,
    output: &mut HostBeginTokenAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut token_auth_request = HostTokenAuthRequest::new(input)?;
    token_auth_request.begin(RequestParam::HostTokenAuthBegin(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(token_auth_request))?;
    Ok(())
}

// HostEndTokenAuth
pub fn host_end_token_auth(
    input: &HostEndTokenAuthInputFfi,
    output: &mut HostEndTokenAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut token_auth_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    token_auth_request.end(RequestParam::HostTokenAuthEnd(input, output))?;
    Ok(())
}

// HostRevokeToken
pub fn host_revoke_token(
    input: &HostRevokeTokenInputFfi,
    _output: &mut HostRevokeTokenOutputFfi,
) -> Result<(), ErrorCode> {
    companion_device_db_helper::delete_companion_device_token(input.template_id)?;
    Ok(())
}

// HostUpdateCompanionStatus
pub fn host_update_companion_status(
    input: &HostUpdateCompanionStatusInputFfi,
    _output: &mut HostUpdateCompanionStatusOutputFfi,
) -> Result<(), ErrorCode> {
    companion_device_db_helper::update_companion_device_info(
        input.template_id,
        input.device_model_info.to_string()?,
        input.device_name.to_string()?,
        input.device_user_name.to_string()?,
    )?;
    Ok(())
}

// HostUpdateCompanionEnabledBusinessIds
pub fn host_update_companion_enabled_business_ids(
    input: &HostUpdateCompanionEnabledBusinessIdsInputFfi,
    _output: &mut HostUpdateCompanionEnabledBusinessIdsOutputFfi,
) -> Result<(), ErrorCode> {
    companion_device_db_helper::update_device_business_id(
        input.template_id,
        Vec::<i32>::try_from(input.business_ids).map_err(|e| p!(e))?,
    )?;
    Ok(())
}

// HostSetCompanionInvalid
pub fn host_set_companion_invalid(
    input: &HostSetCompanionInvalidInputFfi,
    _output: &mut HostSetCompanionInvalidOutputFfi,
) -> Result<(), ErrorCode> {
    companion_device_db_helper::update_companion_device_valid_flag(input.template_id, false)?;
    Ok(())
}

// HostBeginDelegateAuth
pub fn host_begin_delegate_auth(
    input: &HostBeginDelegateAuthInputFfi,
    output: &mut HostBeginDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut delegate_auth_request = HostDelegateAuthRequest::new(input)?;
    delegate_auth_request.begin(RequestParam::HostDelegateAuthBegin(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(delegate_auth_request))?;
    Ok(())
}

// HostEndDelegateAuth
pub fn host_end_delegate_auth(
    input: &HostEndDelegateAuthInputFfi,
    output: &mut HostEndDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut delegate_auth_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    delegate_auth_request.end(RequestParam::HostDelegateAuthEnd(input, output))?;
    Ok(())
}

// HostCancelDelegateAuth
pub fn host_cancel_delegate_auth(
    input: &HostCancelDelegateAuthInputFfi,
    _output: &mut HostCancelDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// HostProcessPreObtainToken
pub fn host_process_pre_obtain_token(
    input: &HostProcessPreObtainTokenInputFfi,
    output: &mut HostProcessPreObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut obtain_token_request = HostDeviceObtainTokenRequest::new(input)?;
    obtain_token_request.begin(RequestParam::HostObtainTokenBegin(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(obtain_token_request))?;
    Ok(())
}

// HostProcessObtainToken
pub fn host_process_obtain_token(
    input: &HostProcessObtainTokenInputFfi,
    output: &mut HostProcessObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut obtain_token_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    obtain_token_request.end(RequestParam::HostObtainTokenEnd(input, output))?;
    Ok(())
}

// HostCancelObtainToken
pub fn host_cancel_obtain_token(
    input: &HostCancelObtainTokenInputFfi,
    _output: &mut HostCancelObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// HostCheckTemplateEnrolled
pub fn host_check_template_enrolled(
    input: &HostCheckTemplateEnrolledInputFfi,
    output: &mut HostCheckTemplateEnrolledOutputFfi,
) -> Result<(), ErrorCode> {
    match CompanionDeviceDbManagerRegistry::get().get_device(input.template_id) {
        Ok(_) => {
            log_i!("template_id {:04x} enrolled", input.template_id as u16);
            output.enrolled = 1;
            Ok(())
        },
        Err(ErrorCode::NotFound) => {
            log_i!("template_id {:04x} not enrolled", input.template_id as u16);
            output.enrolled = 0;
            Ok(())
        },
        Err(e) => {
            log_e!("check template_id enrolled failed: {:?}", e);
            Err(e)
        },
    }
}

// HostRefreshToken
pub fn host_refresh_token(
    input: &HostRefreshTokenInputFfi,
    output: &mut HostRefreshTokenOutputFfi,
) -> Result<(), ErrorCode> {
    companion_device_db_helper::check_device_capability(input.template_id, Capability::TokenAuth)?;

    let fwk_msg_info = fwk_msg_validator::decode_and_validate_fwk_msg(
        input.fwk_message.as_slice()?,
        Some(input.template_id),
    )?;
    let atl = fwk_msg_info.atl as i32;

    let device_capabilities =
        CompanionDeviceDbManagerRegistry::get_mut().read_device_capability_info(input.template_id)?;
    let mut max_cached_atl = AuthTrustLevel::Atl0 as i32;
    let mut token_infos = Vec::new();
    for device_capability in &device_capabilities {
        let token_info = match CompanionDeviceDbManagerRegistry::get_mut()
            .get_token(input.template_id, device_capability.processor_type)
        {
            Ok(token_info) => token_info,
            Err(_) => {
                output.need_reissue = true;
                return Ok(());
            },
        };
        if token_info.atl as i32 > max_cached_atl {
            max_cached_atl = token_info.atl as i32;
        }
        let current_time = TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?;
        if current_time > token_info.expire_time {
            log_e!(
                "token is expired, current_time:{}, expire_time:{}",
                current_time,
                token_info.expire_time
            );
            output.need_reissue = true;
            return Ok(());
        }
        if current_time.saturating_sub(token_info.issue_time) > TOKEN_REFRESH_THRESHOLD {
            log_e!(
                "token issue time too old, current_time:{}, issue_time:{}",
                current_time,
                token_info.issue_time
            );
            output.need_reissue = true;
            return Ok(());
        }
        if atl > token_info.atl as i32 {
            output.need_reissue = true;
            return Ok(());
        }
        token_infos.push(token_info);
    }

    let new_expire_time = TimeKeeperRegistry::get()
        .get_rtc_time()
        .map_err(|e| p!(e))?
        .checked_add(TOKEN_VALID_PERIOD)
        .ok_or_else(|| {
            log_e!("expire_time overflow");
            ErrorCode::GeneralError
        })?;
    for mut token_info in token_infos {
        token_info.expire_time = new_expire_time;
        CompanionDeviceDbManagerRegistry::get_mut().update_token(&token_info)?;
    }

    log_i!(
        "refresh token success, template_id:{:04x}, new_expire_time:{}",
        input.template_id as u16,
        new_expire_time
    );

    output.need_reissue = false;
    output.cached_atl = max_cached_atl;
    Ok(())
}

// CompanionGetPersistedStatus
pub fn companion_get_persisted_status(
    input: &CompanionGetPersistedStatusInputFfi,
    output: &mut CompanionGetPersistedStatusOutputFfi,
) -> Result<(), ErrorCode> {
    let mut binding_status_list: Vec<PersistedHostBindingStatusFfi> = Vec::new();
    let device_info_list = HostBindingDbManagerRegistry::get().get_device_list(input.user_id);
    for device_info in device_info_list {
        let binding_status = PersistedHostBindingStatusFfi {
            binding_id: device_info.binding_id,
            companion_user_id: device_info.user_info.user_id,
            host_device_key: DeviceKeyFfi::try_from(device_info.device_key)?,
            is_token_valid: HostBindingDbManagerRegistry::get().is_device_token_valid(device_info.binding_id)?,
        };
        binding_status_list.push(binding_status);
    }
    host_binding_status_vec_to_ffi(binding_status_list, &mut output.binding_status_list)
}

// CompanionProcessCheck
pub fn companion_process_check(
    input: &CompanionProcessCheckInputFfi,
    output: &mut CompanionProcessCheckOutputFfi,
) -> Result<(), ErrorCode> {
    let mut sync_status_request = CompanionDeviceSyncStatusRequest::new(input)?;
    sync_status_request.begin(RequestParam::CompanionSyncStatus(input, output))?;
    Ok(())
}

// CompanionInitKeyNegotiation
pub fn companion_init_key_negotiation(
    input: &CompanionInitKeyNegotiationInputFfi,
    output: &mut CompanionInitKeyNegotiationOutputFfi,
) -> Result<(), ErrorCode> {
    let mut enroll_request = CompanionDeviceEnrollRequest::new(input)?;
    enroll_request.prepare(RequestParam::CompanionKeyNego(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(enroll_request))?;
    Ok(())
}

// CompanionBeginAddHostBinding
pub fn companion_begin_add_host_binding(
    input: &CompanionBeginAddHostBindingInputFfi,
    output: &mut CompanionBeginAddHostBindingOutputFfi,
) -> Result<(), ErrorCode> {
    let enroll_request = RequestManagerRegistry::get_mut().get_request(input.request_id)?;
    enroll_request.begin(RequestParam::CompanionEnrollBegin(input, output))?;
    Ok(())
}

// CompanionEndAddHostBinding
pub fn companion_end_add_host_binding(
    input: &CompanionEndAddHostBindingInputFfi,
    output: &mut CompanionEndAddHostBindingOutputFfi,
) -> Result<(), ErrorCode> {
    let mut enroll_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    enroll_request.end(RequestParam::CompanionEnrollEnd(input, output))?;
    Ok(())
}

// CompanionRemoveHostBinding
pub fn companion_remove_host_binding(
    input: &CompanionRemoveHostBindingInputFfi,
    _output: &mut CompanionRemoveHostBindingOutputFfi,
) -> Result<(), ErrorCode> {
    HostBindingDbManagerRegistry::get_mut().remove_device(input.binding_id)?;
    Ok(())
}

// CompanionPreIssueToken
pub fn companion_pre_issue_token(
    input: &CompanionPreIssueTokenInputFfi,
    output: &mut CompanionPreIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut issue_token_request = CompanionDeviceIssueTokenRequest::new(input)?;
    issue_token_request.begin(RequestParam::CompanionIssueTokenBegin(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(issue_token_request))?;
    Ok(())
}

// CompanionProcessIssueToken
pub fn companion_process_issue_token(
    input: &CompanionProcessIssueTokenInputFfi,
    output: &mut CompanionProcessIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut issue_token_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    issue_token_request.end(RequestParam::CompanionIssueTokenEnd(input, output))?;
    Ok(())
}

// CompanionCancelIssueToken
pub fn companion_cancel_issue_token(
    input: &CompanionCancelIssueTokenInputFfi,
    _output: &mut CompanionCancelIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}

// CompanionProcessTokenAuth
pub fn companion_process_token_auth(
    input: &CompanionProcessTokenAuthInputFfi,
    output: &mut CompanionProcessTokenAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut token_auth_request = CompanionTokenAuthRequest::new(input)?;
    token_auth_request.begin(RequestParam::CompanionTokenAuthBegin(input, output))?;
    Ok(())
}

// CompanionRevokeToken
pub fn companion_revoke_token(
    input: &CompanionRevokeTokenInputFfi,
    _output: &mut CompanionRevokeTokenOutputFfi,
) -> Result<(), ErrorCode> {
    HostBindingDbManagerRegistry::get_mut().delete_device_token(input.binding_id)
}

// CompanionBeginDelegateAuth
pub fn companion_begin_delegate_auth(
    input: &CompanionBeginDelegateAuthInputFfi,
    output: &mut CompanionBeginDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut delegate_auth_request = CompanionDelegateAuthRequest::new(input)?;
    delegate_auth_request.begin(RequestParam::CompanionDelegateAuthBegin(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(delegate_auth_request))?;
    Ok(())
}

// CompanionEndDelegateAuth
pub fn companion_end_delegate_auth(
    input: &CompanionEndDelegateAuthInputFfi,
    output: &mut CompanionEndDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut delegate_auth_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    delegate_auth_request.end(RequestParam::CompanionDelegateAuthEnd(input, output))?;
    Ok(())
}

// CompanionBeginObtainToken
pub fn companion_begin_obtain_token(
    input: &CompanionBeginObtainTokenInputFfi,
    output: &mut CompanionBeginObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut obtain_token_request = CompanionDeviceObtainTokenRequest::new(input)?;
    obtain_token_request.begin(RequestParam::CompanionObtainTokenBegin(input, output))?;
    RequestManagerRegistry::get_mut().add_request(Box::new(obtain_token_request))?;
    Ok(())
}

// CompanionEndObtainToken
pub fn companion_end_obtain_token(
    input: &CompanionEndObtainTokenInputFfi,
    output: &mut CompanionEndObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut obtain_token_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    obtain_token_request.end(RequestParam::CompanionObtainTokenEnd(input, output))?;
    Ok(())
}

// CompanionCancelObtainToken
pub fn companion_cancel_obtain_token(
    input: &CompanionCancelObtainTokenInputFfi,
    _output: &mut CompanionCancelObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    Ok(())
}
