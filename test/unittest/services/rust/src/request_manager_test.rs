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
use crate::traits::request_manager::{DummyRequestManager, Request, RequestManager, RequestParam};
use crate::ut_registry_guard;
use crate::{log_e, log_i};

struct DummyCompanionRequest;

impl Request for DummyCompanionRequest {
    fn get_request_id(&self) -> i32 {
        log_e!("not implemented");
        0
    }
    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn begin(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn end(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

struct DummyHostRequest;

impl Request for DummyHostRequest {
    fn get_request_id(&self) -> i32 {
        log_e!("not implemented");
        0
    }
    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn begin(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
    fn end(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

#[test]
fn dummy_companion_request_manager_test() {
    let _guard = ut_registry_guard!();
    log_i!("dummy_companion_request_manager_test start");

    let mut dummy_companion_request_manager = DummyRequestManager;
    assert_eq!(
        dummy_companion_request_manager.add_request(Box::new(DummyCompanionRequest)),
        Err(ErrorCode::GeneralError)
    );
    assert!(dummy_companion_request_manager.remove_request(0).is_err());
    assert!(dummy_companion_request_manager.get_request(0).is_err());
}

#[test]
fn dummy_host_request_manager_test() {
    let _guard = ut_registry_guard!();
    log_i!("dummy_host_request_manager_test start");

    let mut dummy_host_request_manager = DummyRequestManager;
    assert_eq!(dummy_host_request_manager.add_request(Box::new(DummyHostRequest)), Err(ErrorCode::GeneralError));
    assert!(dummy_host_request_manager.remove_request(0).is_err());
    assert!(dummy_host_request_manager.get_request(0).is_err());
}
