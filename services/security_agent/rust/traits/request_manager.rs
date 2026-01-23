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

use crate::common::constants::*;
use crate::common::types::*;
use crate::entry::companion_device_auth_ffi::{
    CompanionBeginAddHostBindingInputFfi, CompanionBeginAddHostBindingOutputFfi, CompanionBeginDelegateAuthInputFfi,
    CompanionBeginDelegateAuthOutputFfi, CompanionBeginObtainTokenInputFfi, CompanionBeginObtainTokenOutputFfi,
    CompanionEndAddHostBindingInputFfi, CompanionEndAddHostBindingOutputFfi, CompanionEndDelegateAuthInputFfi,
    CompanionEndDelegateAuthOutputFfi, CompanionEndObtainTokenInputFfi, CompanionEndObtainTokenOutputFfi,
    CompanionInitKeyNegotiationInputFfi, CompanionInitKeyNegotiationOutputFfi, CompanionPreIssueTokenInputFfi,
    CompanionPreIssueTokenOutputFfi, CompanionProcessCheckInputFfi, CompanionProcessCheckOutputFfi,
    CompanionProcessIssueTokenInputFfi, CompanionProcessIssueTokenOutputFfi, CompanionProcessTokenAuthInputFfi,
    CompanionProcessTokenAuthOutputFfi,
    HostBeginAddCompanionInputFfi, HostBeginAddCompanionOutputFfi, HostBeginCompanionCheckInputFfi,
    HostBeginCompanionCheckOutputFfi, HostBeginDelegateAuthInputFfi, HostBeginDelegateAuthOutputFfi,
    HostBeginIssueTokenInputFfi, HostBeginIssueTokenOutputFfi, HostBeginTokenAuthInputFfi, HostBeginTokenAuthOutputFfi,
    HostEndAddCompanionInputFfi, HostEndAddCompanionOutputFfi, HostEndCompanionCheckInputFfi,
    HostEndCompanionCheckOutputFfi, HostEndDelegateAuthInputFfi, HostEndDelegateAuthOutputFfi,
    HostEndIssueTokenInputFfi, HostEndIssueTokenOutputFfi, HostEndTokenAuthInputFfi, HostEndTokenAuthOutputFfi,
    HostGetInitKeyNegotiationInputFfi, HostGetInitKeyNegotiationOutputFfi, HostPreIssueTokenInputFfi,
    HostPreIssueTokenOutputFfi, HostProcessObtainTokenInputFfi, HostProcessObtainTokenOutputFfi,
    HostProcessPreObtainTokenInputFfi, HostProcessPreObtainTokenOutputFfi,
};

use crate::traits::crypto_engine::KeyPair;
use crate::traits::db_manager::DeviceKey;
use crate::String;
use crate::{log_e, singleton_registry, Box, Vec};

pub enum RequestParam<'a> {
    CompanionSyncStatus(&'a CompanionProcessCheckInputFfi, &'a mut CompanionProcessCheckOutputFfi),
    CompanionKeyNego(&'a CompanionInitKeyNegotiationInputFfi, &'a mut CompanionInitKeyNegotiationOutputFfi),
    CompanionEnrollBegin(&'a CompanionBeginAddHostBindingInputFfi, &'a mut CompanionBeginAddHostBindingOutputFfi),
    CompanionEnrollEnd(&'a CompanionEndAddHostBindingInputFfi, &'a mut CompanionEndAddHostBindingOutputFfi),
    CompanionTokenAuthBegin(&'a CompanionProcessTokenAuthInputFfi, &'a mut CompanionProcessTokenAuthOutputFfi),
    CompanionTokenAuthEnd(&'a CompanionProcessTokenAuthInputFfi, &'a mut CompanionProcessTokenAuthOutputFfi),
    CompanionDelegateAuthBegin(&'a CompanionBeginDelegateAuthInputFfi, &'a mut CompanionBeginDelegateAuthOutputFfi),
    CompanionDelegateAuthEnd(&'a CompanionEndDelegateAuthInputFfi, &'a mut CompanionEndDelegateAuthOutputFfi),
    CompanionIssueTokenBegin(&'a CompanionPreIssueTokenInputFfi, &'a mut CompanionPreIssueTokenOutputFfi),
    CompanionIssueTokenEnd(&'a CompanionProcessIssueTokenInputFfi, &'a mut CompanionProcessIssueTokenOutputFfi),
    CompanionObtainTokenBegin(&'a CompanionBeginObtainTokenInputFfi, &'a mut CompanionBeginObtainTokenOutputFfi),
    CompanionObtainTokenEnd(&'a CompanionEndObtainTokenInputFfi, &'a mut CompanionEndObtainTokenOutputFfi),
    HostSyncStatusBegin(&'a HostBeginCompanionCheckInputFfi, &'a mut HostBeginCompanionCheckOutputFfi),
    HostSyncStatusEnd(&'a HostEndCompanionCheckInputFfi, &'a mut HostEndCompanionCheckOutputFfi),
    HostKeyNego(&'a HostGetInitKeyNegotiationInputFfi, &'a mut HostGetInitKeyNegotiationOutputFfi),
    HostEnrollBegin(&'a HostBeginAddCompanionInputFfi, &'a mut HostBeginAddCompanionOutputFfi),
    HostEnrollEnd(&'a HostEndAddCompanionInputFfi, &'a mut HostEndAddCompanionOutputFfi),
    HostTokenAuthBegin(&'a HostBeginTokenAuthInputFfi, &'a mut HostBeginTokenAuthOutputFfi),
    HostTokenAuthEnd(&'a HostEndTokenAuthInputFfi, &'a mut HostEndTokenAuthOutputFfi),
    HostDelegateAuthBegin(&'a HostBeginDelegateAuthInputFfi, &'a mut HostBeginDelegateAuthOutputFfi),
    HostDelegateAuthEnd(&'a HostEndDelegateAuthInputFfi, &'a mut HostEndDelegateAuthOutputFfi),
    HostIssueTokenPrepare(&'a HostPreIssueTokenInputFfi, &'a mut HostPreIssueTokenOutputFfi),
    HostIssueTokenBegin(&'a HostBeginIssueTokenInputFfi, &'a mut HostBeginIssueTokenOutputFfi),
    HostIssueTokenEnd(&'a HostEndIssueTokenInputFfi, &'a mut HostEndIssueTokenOutputFfi),
    HostObtainTokenBegin(&'a HostProcessPreObtainTokenInputFfi, &'a mut HostProcessPreObtainTokenOutputFfi),
    HostObtainTokenEnd(&'a HostProcessObtainTokenInputFfi, &'a mut HostProcessObtainTokenOutputFfi),
}

pub trait Request {
    fn get_request_id(&self) -> i32;

    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("begin not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn end(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("end not implemented");
        Err(ErrorCode::GeneralError)
    }
}

pub type DynRequest = dyn Request;

pub trait RequestManager {
    fn add_request(&mut self, request: Box<DynRequest>) -> Result<(), ErrorCode>;
    fn remove_request(&mut self, request_id: i32) -> Result<Box<DynRequest>, ErrorCode>;
    fn get_request<'a>(&'a mut self, request_id: i32) -> Result<&'a mut DynRequest, ErrorCode>;
}

pub struct DummyRequestManager;

impl RequestManager for DummyRequestManager {
    fn add_request(&mut self, _request: Box<DynRequest>) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn remove_request(&mut self, _request_id: i32) -> Result<Box<DynRequest>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_request<'a>(&'a mut self, _request_id: i32) -> Result<&'a mut DynRequest, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(RequestManagerRegistry, RequestManager, DummyRequestManager);

#[cfg(any(test, feature = "test-utils"))]
pub use crate::test_utils::mock::MockRequestManager;
