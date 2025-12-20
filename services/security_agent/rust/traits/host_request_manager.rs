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

use crate::common::constants::*;
use crate::common::types::*;
use crate::entry::companion_device_auth_ffi::{
    HostBeginAddCompanionInputFfi, HostBeginAddCompanionOutputFfi, HostBeginCompanionCheckInputFfi,
    HostBeginCompanionCheckOutputFfi, HostBeginDelegateAuthInputFfi,
    HostBeginDelegateAuthOutputFfi, HostBeginIssueTokenInputFfi, HostBeginIssueTokenOutputFfi,
    HostBeginTokenAuthInputFfi, HostBeginTokenAuthOutputFfi, HostEndAddCompanionInputFfi,
    HostEndAddCompanionOutputFfi, HostEndCompanionCheckInputFfi, HostEndCompanionCheckOutputFfi,
    HostEndDelegateAuthInputFfi, HostEndDelegateAuthOutputFfi, HostEndIssueTokenInputFfi,
    HostEndIssueTokenOutputFfi, HostEndTokenAuthInputFfi, HostEndTokenAuthOutputFfi,
    HostGetInitKeyNegotiationInputFfi, HostGetInitKeyNegotiationOutputFfi,
    HostPreIssueTokenInputFfi, HostPreIssueTokenOutputFfi, HostProcessObtainTokenInputFfi,
    HostProcessObtainTokenOutputFfi, HostProcessPreObtainTokenInputFfi,
    HostProcessPreObtainTokenOutputFfi,
};

use crate::String;
use crate::{log_e, singleton_registry, Box, Vec};

pub enum HostRequestInput {
    SyncStatusBegin(HostBeginCompanionCheckInputFfi),
    SyncStatusEnd(HostEndCompanionCheckInputFfi),
    KeyNego(HostGetInitKeyNegotiationInputFfi),
    EnrollBegin(HostBeginAddCompanionInputFfi),
    EnrollEnd(HostEndAddCompanionInputFfi),
    TokenAuthBegin(HostBeginTokenAuthInputFfi),
    TokenAuthEnd(HostEndTokenAuthInputFfi),
    DelegateAuthBegin(HostBeginDelegateAuthInputFfi),
    DelegateAuthEnd(HostEndDelegateAuthInputFfi),
    IssueTokenPrepare(HostPreIssueTokenInputFfi),
    IssueTokenBegin(HostBeginIssueTokenInputFfi),
    IssueTokenEnd(HostEndIssueTokenInputFfi),
    ObtainTokenBegin(HostProcessPreObtainTokenInputFfi),
    ObtainTokenEnd(HostProcessObtainTokenInputFfi),
}

pub enum HostRequestOutput {
    SyncStatusBegin(HostBeginCompanionCheckOutputFfi),
    SyncStatusEnd(HostEndCompanionCheckOutputFfi),
    KeyNego(HostGetInitKeyNegotiationOutputFfi),
    EnrollBegin(HostBeginAddCompanionOutputFfi),
    EnrollEnd(HostEndAddCompanionOutputFfi),
    TokenAuthBegin(HostBeginTokenAuthOutputFfi),
    TokenAuthEnd(HostEndTokenAuthOutputFfi),
    DelegateAuthBegin(HostBeginDelegateAuthOutputFfi),
    DelegateAuthEnd(HostEndDelegateAuthOutputFfi),
    IssueTokenPrepare(HostPreIssueTokenOutputFfi),
    IssueTokenBegin(HostBeginIssueTokenOutputFfi),
    IssueTokenEnd(HostEndIssueTokenOutputFfi),
    ObtainTokenBegin(HostProcessPreObtainTokenOutputFfi),
    ObtainTokenEnd(HostProcessObtainTokenOutputFfi),
}

pub trait HostRequest {
    fn get_request_id(&self) -> i32;
    fn prepare(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode>;
    fn begin(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode>;
    fn end(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode>;
}

pub type DynHostRequest = dyn HostRequest;

pub trait HostRequestManager {
    fn add_request(&mut self, request: Box<DynHostRequest>) -> Result<(), ErrorCode>;
    fn remove_request(&mut self, request_id: i32) -> Result<Box<DynHostRequest>, ErrorCode>;
    fn get_request(&mut self, request_id: i32) -> Result<&mut DynHostRequest, ErrorCode>;
}

pub struct DummyHostRequestManager;

impl HostRequestManager for DummyHostRequestManager {
    fn add_request(&mut self, _request: Box<DynHostRequest>) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn remove_request(&mut self, _request_id: i32) -> Result<Box<DynHostRequest>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_request(&mut self, _request_id: i32) -> Result<&mut DynHostRequest, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(
    HostRequestManagerRegistry,
    HostRequestManager,
    DummyHostRequestManager
);
