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
    CompanionBeginAddHostBindingInputFfi, CompanionBeginAddHostBindingOutputFfi, CompanionBeginDelegateAuthInputFfi,
    CompanionBeginDelegateAuthOutputFfi, CompanionBeginObtainTokenInputFfi, CompanionBeginObtainTokenOutputFfi,
    CompanionEndAddHostBindingInputFfi, CompanionEndAddHostBindingOutputFfi, CompanionEndDelegateAuthInputFfi,
    CompanionEndDelegateAuthOutputFfi, CompanionEndObtainTokenInputFfi, CompanionEndObtainTokenOutputFfi,
    CompanionInitKeyNegotiationInputFfi, CompanionInitKeyNegotiationOutputFfi, CompanionPreIssueTokenInputFfi,
    CompanionPreIssueTokenOutputFfi, CompanionProcessCheckInputFfi, CompanionProcessCheckOutputFfi,
    CompanionProcessIssueTokenInputFfi, CompanionProcessIssueTokenOutputFfi, CompanionProcessTokenAuthInputFfi,
    CompanionProcessTokenAuthOutputFfi,
};

use crate::traits::crypto_engine::KeyPair;
use crate::traits::db_manager::DeviceKey;
use crate::String;
use crate::{log_e, singleton_registry, Box, Vec};

pub enum CompanionRequestParam<'a> {
    SyncStatus(&'a CompanionProcessCheckInputFfi, &'a mut CompanionProcessCheckOutputFfi),
    KeyNego(&'a CompanionInitKeyNegotiationInputFfi, &'a mut CompanionInitKeyNegotiationOutputFfi),
    EnrollBegin(&'a CompanionBeginAddHostBindingInputFfi, &'a mut CompanionBeginAddHostBindingOutputFfi),
    EnrollEnd(&'a CompanionEndAddHostBindingInputFfi, &'a mut CompanionEndAddHostBindingOutputFfi),
    TokenAuthBegin(&'a CompanionProcessTokenAuthInputFfi, &'a mut CompanionProcessTokenAuthOutputFfi),
    TokenAuthEnd(&'a CompanionProcessTokenAuthInputFfi, &'a mut CompanionProcessTokenAuthOutputFfi),
    DelegateAuthBegin(&'a CompanionBeginDelegateAuthInputFfi, &'a mut CompanionBeginDelegateAuthOutputFfi),
    DelegateAuthEnd(&'a CompanionEndDelegateAuthInputFfi, &'a mut CompanionEndDelegateAuthOutputFfi),
    IssueTokenBegin(&'a CompanionPreIssueTokenInputFfi, &'a mut CompanionPreIssueTokenOutputFfi),
    IssueTokenEnd(&'a CompanionProcessIssueTokenInputFfi, &'a mut CompanionProcessIssueTokenOutputFfi),
    ObtainTokenBegin(&'a CompanionBeginObtainTokenInputFfi, &'a mut CompanionBeginObtainTokenOutputFfi),
    ObtainTokenEnd(&'a CompanionEndObtainTokenInputFfi, &'a mut CompanionEndObtainTokenOutputFfi),
}

pub trait CompanionRequest {
    fn get_request_id(&self) -> i32;

    fn prepare(&mut self, _param: CompanionRequestParam) -> Result<(), ErrorCode> {
        log_e!("prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, _param: CompanionRequestParam) -> Result<(), ErrorCode> {
        log_e!("begin not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn end(&mut self, _param: CompanionRequestParam) -> Result<(), ErrorCode> {
        log_e!("end not implemented");
        Err(ErrorCode::GeneralError)
    }
}

pub type DynCompanionRequest = dyn CompanionRequest;

pub trait CompanionRequestManager {
    fn add_request(&mut self, request: Box<DynCompanionRequest>) -> Result<(), ErrorCode>;
    fn remove_request(&mut self, request_id: i32) -> Result<Box<DynCompanionRequest>, ErrorCode>;
    fn get_request<'a>(&'a mut self, request_id: i32) -> Result<&'a mut DynCompanionRequest, ErrorCode>;
}

pub struct DummyCompanionRequestManager;

impl CompanionRequestManager for DummyCompanionRequestManager {
    fn add_request(&mut self, _request: Box<DynCompanionRequest>) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn remove_request(&mut self, _request_id: i32) -> Result<Box<DynCompanionRequest>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn get_request<'a>(&'a mut self, _request_id: i32) -> Result<&'a mut DynCompanionRequest, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(CompanionRequestManagerRegistry, CompanionRequestManager, DummyCompanionRequestManager);

#[cfg(any(test, feature = "test-utils"))]
pub use crate::test_utils::mock::MockCompanionRequestManager;
