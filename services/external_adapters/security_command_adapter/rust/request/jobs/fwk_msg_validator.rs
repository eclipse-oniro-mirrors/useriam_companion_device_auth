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

use crate::common::constants::{AuthTrustLevel, AuthType, ErrorCode, FWK_MSG_MAX_AGE_MS};
use crate::entry::companion_device_auth_ffi::PROPERTY_MODE_UNFREEZE;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::traits::log_trace::RustFileId;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::AttributeKey;
use crate::{log_e, p, Vec};

pub(crate) const FILE_ID: u16 = RustFileId::FwkMsgValidator as u16;

#[derive(Debug, Clone, PartialEq)]
pub struct FwkMsgInfo {
    pub atl: AuthTrustLevel,
    pub template_ids: Vec<u64>,
}

pub fn decode_and_validate_fwk_msg(
    fwk_message: &[u8],
    expected_template_id: Option<u64>,
) -> Result<FwkMsgInfo, ErrorCode> {
    let pub_key = MiscManagerRegistry::get_mut().get_fwk_pub_key().map_err(|e| p!(e))?;
    let message_codec = MessageCodec::new(MessageSignParam::Framework(pub_key));
    let attribute = message_codec.deserialize_attribute(fwk_message).map_err(|e| p!(e))?;

    let property_mode = attribute.get_u32(AttributeKey::AttrPropertyMode).map_err(|e| p!(e))?;
    if property_mode != PROPERTY_MODE_UNFREEZE {
        log_e!("property_mode is not unfreeze: {}", property_mode);
        return Err(ErrorCode::GeneralError);
    }

    let auth_type = attribute.get_u32(AttributeKey::AttrType).map_err(|e| p!(e))?;
    if auth_type != AuthType::CompanionDevice as u32 {
        log_e!("auth_type is not companionDevice: {}", auth_type);
        return Err(ErrorCode::GeneralError);
    }

    let template_ids = attribute.get_u64_vec(AttributeKey::AttrTemplateIdList).map_err(|e| p!(e))?;
    if let Some(tid) = expected_template_id {
        if !template_ids.contains(&tid) {
            log_e!("template_id check fail");
            return Err(ErrorCode::GeneralError);
        }
    }

    let atl = AuthTrustLevel::try_from(attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?)
        .map_err(|_| {
            log_e!("Invalid ATL value");
            ErrorCode::GeneralError
        })?;

    let fwk_time = attribute.get_u64(AttributeKey::AttrTimeStamp).map_err(|e| p!(e))?;
    let now = TimeKeeperRegistry::get().get_system_time().map_err(|e| p!(e))?;
    if now < fwk_time || now - fwk_time > FWK_MSG_MAX_AGE_MS {
        log_e!("fwk_msg expired, fwk_time:{} now:{}", fwk_time, now);
        return Err(ErrorCode::GeneralError);
    }

    Ok(FwkMsgInfo { atl, template_ids })
}
