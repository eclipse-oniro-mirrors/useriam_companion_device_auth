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
use crate::common::constants::*;
use crate::entry::companion_device_auth_ffi::*;
use crate::jobs::host_db_helper;
use crate::request::delegate_auth::companion_auth::CompanionDelegateAuthRequest;
use crate::request::delegate_auth::host_auth::HostDelegateAuthRequest;
use crate::request::enroll::companion_enroll::CompanionDeviceEnrollRequest;
use crate::request::enroll::host_enroll::HostDeviceEnrollRequest;
use crate::request::status_sync::companion_sync_status::CompanionDeviceSyncStatusRequest;
use crate::request::status_sync::host_sync_status::HostDeviceSyncStatusRequest;
use crate::request::token_auth::companion_auth::CompanionTokenAuthRequest;
use crate::request::token_auth::host_auth::HostTokenAuthRequest;
use crate::request::token_issue::companion_issue_token::CompanionDeviceIssueTokenRequest;
use crate::request::token_issue::host_issue_token::HostDeviceIssueTokenRequest;
use crate::request::token_obtain::companion_obtain_token::CompanionDeviceObtainTokenRequest;
use crate::request::token_obtain::host_obtain_token::HostDeviceObtainTokenRequest;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::request_manager::{Request, RequestManagerRegistry, RequestParam};
use crate::utils::message_codec::MessageCodec;
use crate::utils::message_codec::MessageSignParam;
use crate::utils::AttributeKey;
use crate::{log_e, log_i, p, Box, Vec};
use core::convert::TryFrom;

#[allow(dead_code)]
static mut INIT_FLAG: bool = false;

// Init
pub fn init(_input: &InitInputFfi, _output: &mut InitOutputFfi) -> Result<(), ErrorCode> {
    let key_pair = CryptoEngineRegistry::get().generate_ed25519_key_pair().map_err(|e| p!(e))?;
    MiscManagerRegistry::get_mut().set_local_key_pair(key_pair).map_err(|e| p!(e))?;

    CompanionDbManagerRegistry::get_mut().read_device_db().map_err(|e| p!(e))?;
    HostDbManagerRegistry::get_mut().read_device_db().map_err(|e| p!(e))?;
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
    host_db_helper::verify_template(input.template_ids.try_into().map_err(|e| p!(e))?)?;
    Ok(())
}

// HostGetPersistedStatus
pub fn host_get_persisted_status(
    input: &HostGetPersistedStatusInputFfi,
    output: &mut HostGetPersistedStatusOutputFfi,
) -> Result<(), ErrorCode> {
    let mut companion_status_list: Vec<PersistedCompanionStatusFfi> = Vec::new();
    match host_db_helper::get_companion_device_by_user_id(input.user_id) {
        Ok(device_list) => {
            for device_info in device_list {
                let device_base_info =
                    HostDbManagerRegistry::get_mut().read_device_base_info(device_info.template_id)?;

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
    let param = RequestParam::HostSyncStatusBegin(input, output);
    sync_status_request.begin(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(sync_status_request))?;
    Ok(())
}

// HostEndCompanionCheck
pub fn host_end_companion_check(
    input: &HostEndCompanionCheckInputFfi,
    output: &mut HostEndCompanionCheckOutputFfi,
) -> Result<(), ErrorCode> {
    let mut sync_status_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::HostSyncStatusEnd(input, output);
    sync_status_request.end(param)?;
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
    let param = RequestParam::HostKeyNego(input, output);
    enroll_request.prepare(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(enroll_request))?;
    Ok(())
}

// HostBeginAddCompanion
pub fn host_begin_add_companion(
    input: &HostBeginAddCompanionInputFfi,
    output: &mut HostBeginAddCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    let enroll_request = RequestManagerRegistry::get_mut().get_request(input.request_id)?;
    let param = RequestParam::HostEnrollBegin(input, output);
    enroll_request.begin(param)?;
    Ok(())
}

// HostEndAddCompanion
pub fn host_end_add_companion(
    input: &HostEndAddCompanionInputFfi,
    output: &mut HostEndAddCompanionOutputFfi,
) -> Result<(), ErrorCode> {
    let mut enroll_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::HostEnrollEnd(input, output);
    enroll_request.end(param)?;
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
    let device_info = HostDbManagerRegistry::get().get_device(input.template_id)?;
    let user_id = device_info.user_info.user_id;
    let companion_device_key = DeviceKeyFfi::try_from(device_info.device_key)?;
    HostDbManagerRegistry::get_mut().remove_device(input.template_id)?;
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
    let param = RequestParam::HostIssueTokenPrepare(input, output);
    issue_token_request.prepare(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(issue_token_request))?;
    Ok(())
}

// HostBeginIssueToken
pub fn host_begin_issue_token(
    input: &HostBeginIssueTokenInputFfi,
    output: &mut HostBeginIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let issue_token_request: &mut dyn Request = RequestManagerRegistry::get_mut().get_request(input.request_id)?;
    let param = RequestParam::HostIssueTokenBegin(input, output);
    issue_token_request.begin(param)?;
    Ok(())
}

// HostEndIssueToken
pub fn host_end_issue_token(
    input: &HostEndIssueTokenInputFfi,
    output: &mut HostEndIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut issue_token_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::HostIssueTokenEnd(input, output);
    issue_token_request.end(param)?;
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
    let param = RequestParam::HostTokenAuthBegin(input, output);
    token_auth_request.begin(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(token_auth_request))?;
    Ok(())
}

// HostEndTokenAuth
pub fn host_end_token_auth(
    input: &HostEndTokenAuthInputFfi,
    output: &mut HostEndTokenAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut token_auth_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::HostTokenAuthEnd(input, output);
    token_auth_request.end(param)?;
    Ok(())
}

// HostRevokeToken
pub fn host_revoke_token(
    input: &HostRevokeTokenInputFfi,
    _output: &mut HostRevokeTokenOutputFfi,
) -> Result<(), ErrorCode> {
    host_db_helper::delete_companion_device_token(input.template_id)?;
    Ok(())
}

// HostUpdateCompanionStatus
pub fn host_update_companion_status(
    input: &HostUpdateCompanionStatusInputFfi,
    _output: &mut HostUpdateCompanionStatusOutputFfi,
) -> Result<(), ErrorCode> {
    host_db_helper::update_companion_device_info(
        input.template_id,
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
    host_db_helper::update_device_business_id(
        input.template_id,
        Vec::<i32>::try_from(input.business_ids).map_err(|e| p!(e))?,
    )?;
    Ok(())
}

// HostBeginDelegateAuth
pub fn host_begin_delegate_auth(
    input: &HostBeginDelegateAuthInputFfi,
    output: &mut HostBeginDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut delegate_auth_request = HostDelegateAuthRequest::new(input)?;
    let param = RequestParam::HostDelegateAuthBegin(input, output);
    delegate_auth_request.begin(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(delegate_auth_request))?;
    Ok(())
}

// HostEndDelegateAuth
pub fn host_end_delegate_auth(
    input: &HostEndDelegateAuthInputFfi,
    output: &mut HostEndDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut delegate_auth_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::HostDelegateAuthEnd(input, output);
    delegate_auth_request.end(param)?;
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
    let param = RequestParam::HostObtainTokenBegin(input, output);
    obtain_token_request.begin(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(obtain_token_request))?;
    Ok(())
}

// HostProcessObtainToken
pub fn host_process_obtain_token(
    input: &HostProcessObtainTokenInputFfi,
    output: &mut HostProcessObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut obtain_token_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::HostObtainTokenEnd(input, output);
    obtain_token_request.end(param)?;
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
    match HostDbManagerRegistry::get().get_device(input.template_id) {
        Ok(_) => {
            log_i!("template_id {:x} enrolled", input.template_id as u16);
            output.enrolled = 1;
            Ok(())
        },
        Err(ErrorCode::NotFound) => {
            log_i!("template_id {:x} not enrolled", input.template_id as u16);
            output.enrolled = 0;
            Ok(())
        },
        Err(e) => {
            log_e!("check template_id enrolled failed: {:?}", e);
            Err(e)
        },
    }
}

pub fn host_update_token(
    input: &HostUpdateTokenInputFfi,
    output: &mut HostUpdateTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let pub_key = MiscManagerRegistry::get_mut().get_fwk_pub_key().map_err(|e| p!(e))?;
    let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
    let attribute = message_codec
        .deserialize_attribute(input.fwk_message.as_slice()?)
        .map_err(|e| p!(e))?;
    let atl = attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;
    let device_capabilitys = HostDbManagerRegistry::get_mut().read_device_capability_info(input.template_id)?;
    for device_capability in device_capabilitys {
        match HostDbManagerRegistry::get_mut().get_token(input.template_id, device_capability.device_type) {
            Ok(token_info) => {
                if token_info.atl as i32 != atl {
                    output.need_redistribute = true;
                    return Ok(());
                }
            },
            Err(_) => {
                output.need_redistribute = true;
                return Ok(());
            },
        }
    }

    Ok(())
}

// CompanionGetPersistedStatus
pub fn companion_get_persisted_status(
    input: &CompanionGetPersistedStatusInputFfi,
    output: &mut CompanionGetPersistedStatusOutputFfi,
) -> Result<(), ErrorCode> {
    let mut binding_status_list: Vec<PersistedHostBindingStatusFfi> = Vec::new();
    let device_info_list = CompanionDbManagerRegistry::get().get_device_list(input.user_id);
    for device_info in device_info_list {
        let binding_status = PersistedHostBindingStatusFfi {
            binding_id: device_info.binding_id,
            companion_user_id: device_info.user_info.user_id,
            host_device_key: DeviceKeyFfi::try_from(device_info.device_key)?,
            is_token_valid: CompanionDbManagerRegistry::get().is_device_token_valid(device_info.binding_id)?,
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
    let param = RequestParam::CompanionSyncStatus(input, output);
    sync_status_request.begin(param)?;
    Ok(())
}

// CompanionInitKeyNegotiation
pub fn companion_init_key_negotiation(
    input: &CompanionInitKeyNegotiationInputFfi,
    output: &mut CompanionInitKeyNegotiationOutputFfi,
) -> Result<(), ErrorCode> {
    let mut enroll_request = CompanionDeviceEnrollRequest::new(input)?;
    let param = RequestParam::CompanionKeyNego(input, output);
    enroll_request.prepare(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(enroll_request))?;
    Ok(())
}

// CompanionBeginAddHostBinding
pub fn companion_begin_add_host_binding(
    input: &CompanionBeginAddHostBindingInputFfi,
    output: &mut CompanionBeginAddHostBindingOutputFfi,
) -> Result<(), ErrorCode> {
    let enroll_request = RequestManagerRegistry::get_mut().get_request(input.request_id)?;
    let param = RequestParam::CompanionEnrollBegin(input, output);
    enroll_request.begin(param)?;
    Ok(())
}

// CompanionEndAddHostBinding
pub fn companion_end_add_host_binding(
    input: &CompanionEndAddHostBindingInputFfi,
    output: &mut CompanionEndAddHostBindingOutputFfi,
) -> Result<(), ErrorCode> {
    let mut enroll_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::CompanionEnrollEnd(input, output);
    enroll_request.end(param)?;
    Ok(())
}

// CompanionRemoveHostBinding
pub fn companion_remove_host_binding(
    input: &CompanionRemoveHostBindingInputFfi,
    _output: &mut CompanionRemoveHostBindingOutputFfi,
) -> Result<(), ErrorCode> {
    CompanionDbManagerRegistry::get_mut().remove_device(input.binding_id)?;
    Ok(())
}

// CompanionPreIssueToken
pub fn companion_pre_issue_token(
    input: &CompanionPreIssueTokenInputFfi,
    output: &mut CompanionPreIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut issue_token_request = CompanionDeviceIssueTokenRequest::new(input)?;
    let param = RequestParam::CompanionIssueTokenBegin(input, output);
    issue_token_request.begin(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(issue_token_request))?;
    Ok(())
}

// CompanionProcessIssueToken
pub fn companion_process_issue_token(
    input: &CompanionProcessIssueTokenInputFfi,
    output: &mut CompanionProcessIssueTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut issue_token_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::CompanionIssueTokenEnd(input, output);
    issue_token_request.end(param)?;
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
    let param = RequestParam::CompanionTokenAuthBegin(input, output);
    token_auth_request.begin(param)?;
    Ok(())
}

// CompanionRevokeToken
pub fn companion_revoke_token(
    input: &CompanionRevokeTokenInputFfi,
    _output: &mut CompanionRevokeTokenOutputFfi,
) -> Result<(), ErrorCode> {
    CompanionDbManagerRegistry::get_mut().delete_device_token(input.binding_id)
}

// CompanionBeginDelegateAuth
pub fn companion_begin_delegate_auth(
    input: &CompanionBeginDelegateAuthInputFfi,
    output: &mut CompanionBeginDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut delagate_auth_request = CompanionDelegateAuthRequest::new(input)?;
    let param = RequestParam::CompanionDelegateAuthBegin(input, output);
    delagate_auth_request.begin(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(delagate_auth_request))?;
    Ok(())
}

// CompanionEndDelegateAuth
pub fn companion_end_delegate_auth(
    input: &CompanionEndDelegateAuthInputFfi,
    output: &mut CompanionEndDelegateAuthOutputFfi,
) -> Result<(), ErrorCode> {
    let mut delagate_auth_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::CompanionDelegateAuthEnd(input, output);
    delagate_auth_request.end(param)?;
    Ok(())
}

// CompanionBeginObtainToken
pub fn companion_begin_obtain_token(
    input: &CompanionBeginObtainTokenInputFfi,
    output: &mut CompanionBeginObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut obtain_token_request = CompanionDeviceObtainTokenRequest::new(input)?;
    let param = RequestParam::CompanionObtainTokenBegin(input, output);
    obtain_token_request.begin(param)?;
    RequestManagerRegistry::get_mut().add_request(Box::new(obtain_token_request))?;
    Ok(())
}

// CompanionEndObtainToken
pub fn companion_end_obtain_token(
    input: &CompanionEndObtainTokenInputFfi,
    output: &mut CompanionEndObtainTokenOutputFfi,
) -> Result<(), ErrorCode> {
    let mut obtain_token_request = RequestManagerRegistry::get_mut().remove_request(input.request_id)?;
    let param = RequestParam::CompanionObtainTokenEnd(input, output);
    obtain_token_request.end(param)?;
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
