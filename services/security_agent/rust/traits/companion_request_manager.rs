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

pub enum CompanionRequestInput {
    SyncStatus(CompanionProcessCheckInputFfi),
    KeyNego(CompanionInitKeyNegotiationInputFfi),
    EnrollBegin(CompanionBeginAddHostBindingInputFfi),
    EnrollEnd(CompanionEndAddHostBindingInputFfi),
    TokenAuthBegin(CompanionProcessTokenAuthInputFfi),
    TokenAuthEnd(CompanionProcessTokenAuthInputFfi),
    DelegateAuthBegin(CompanionBeginDelegateAuthInputFfi),
    DelegateAuthEnd(CompanionEndDelegateAuthInputFfi),
    IssueTokenBegin(CompanionPreIssueTokenInputFfi),
    IssueTokenEnd(CompanionProcessIssueTokenInputFfi),
    ObtainTokenBegin(CompanionBeginObtainTokenInputFfi),
    ObtainTokenEnd(CompanionEndObtainTokenInputFfi),
}

pub enum CompanionRequestOutput {
    SyncStatus(CompanionProcessCheckOutputFfi),
    KeyNego(CompanionInitKeyNegotiationOutputFfi),
    EnrollBegin(CompanionBeginAddHostBindingOutputFfi),
    EnrollEnd(CompanionEndAddHostBindingOutputFfi),
    TokenAuthBegin(CompanionProcessTokenAuthOutputFfi),
    TokenAuthEnd(CompanionProcessTokenAuthOutputFfi),
    DelegateAuthBegin(CompanionBeginDelegateAuthOutputFfi),
    DelegateAuthEnd(CompanionEndDelegateAuthOutputFfi),
    IssueTokenBegin(CompanionPreIssueTokenOutputFfi),
    IssueTokenEnd(CompanionProcessIssueTokenOutputFfi),
    ObtainTokenBegin(CompanionBeginObtainTokenOutputFfi),
    ObtainTokenEnd(CompanionEndObtainTokenOutputFfi),
}

pub trait CompanionRequest {
    fn get_request_id(&self) -> i32;
    fn prepare(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode>;
    fn begin(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode>;
    fn end(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode>;
}

pub type DynCompanionRequest = dyn CompanionRequest;

pub trait CompanionRequestManager {
    fn add_request(&mut self, request: Box<DynCompanionRequest>) -> Result<(), ErrorCode>;
    fn remove_request(&mut self, request_id: i32) -> Result<Box<DynCompanionRequest>, ErrorCode>;
    fn get_request(&mut self, request_id: i32) -> Result<&mut DynCompanionRequest, ErrorCode>;
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
    fn get_request(&mut self, _request_id: i32) -> Result<&mut DynCompanionRequest, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(CompanionRequestManagerRegistry, CompanionRequestManager, DummyCompanionRequestManager);

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyCompanionRequest;

    impl CompanionRequest for DummyCompanionRequest {
        fn get_request_id(&self) -> i32 {
            log_e!("not implemented");
            0
        }
        fn prepare(&mut self, _input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
            log_e!("not implemented");
            Err(ErrorCode::GeneralError)
        }
        fn begin(&mut self, _input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
            log_e!("not implemented");
            Err(ErrorCode::GeneralError)
        }
        fn end(&mut self, _input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
            log_e!("not implemented");
            Err(ErrorCode::GeneralError)
        }
    }

    #[test]
    fn dummy_companion_request_manager_test() {
        let mut dummy_companion_request_manager = DummyCompanionRequestManager;
        assert_eq!(
            dummy_companion_request_manager.add_request(Box::new(DummyCompanionRequest)),
            Err(ErrorCode::GeneralError)
        );
        assert!(dummy_companion_request_manager.remove_request(0).is_err());
        assert!(dummy_companion_request_manager.get_request(0).is_err());
    }
}
