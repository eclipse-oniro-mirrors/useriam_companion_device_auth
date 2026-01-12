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
use crate::traits::companion_request_manager::{CompanionRequest, CompanionRequestManager, DynCompanionRequest};
use crate::traits::db_manager::DeviceKey;
use crate::{log_e, log_i, p, Box, Vec};

const MAX_REQUEST_NUM: usize = 50;

pub struct DefaultCompanionRequestManager {
    requests: Vec<Box<DynCompanionRequest>>,
}

impl DefaultCompanionRequestManager {
    pub fn new() -> Self {
        Self { requests: Vec::with_capacity(MAX_REQUEST_NUM) }
    }
}

impl CompanionRequestManager for DefaultCompanionRequestManager {
    fn add_request(&mut self, request: Box<DynCompanionRequest>) -> Result<(), ErrorCode> {
        log_i!("add_request start");
        let request_id = request.get_request_id();
        if self.requests.iter().any(|req| req.get_request_id() == request_id) {
            log_e!("request with id {} already exists", request_id);
            return Err(ErrorCode::IdExists);
        }

        if self.requests.len() >= MAX_REQUEST_NUM {
            log_e!("request is reached limit");
            self.requests.remove(0);
        }

        self.requests.push(request);
        Ok(())
    }

    fn remove_request(&mut self, request_id: i32) -> Result<Box<DynCompanionRequest>, ErrorCode> {
        log_i!("remove_request start");
        let pos = self
            .requests
            .iter()
            .position(|req| req.get_request_id() == request_id)
            .ok_or(ErrorCode::NotFound)?;

        Ok(self.requests.remove(pos))
    }

    fn get_request<'a>(&'a mut self, request_id: i32) -> Result<&'a mut DynCompanionRequest, ErrorCode> {
        log_i!("get_request start");
        for request in &mut self.requests {
            if request.get_request_id() == request_id {
                return Ok(request.as_mut());
            }
        }
        Err(ErrorCode::NotFound)
    }
}
