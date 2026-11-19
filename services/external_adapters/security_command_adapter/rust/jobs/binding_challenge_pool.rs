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

use crate::common::constants::{
    ErrorCode, BINDING_SIGNATURE_CHALLENGE_LEN, BINDING_SIGNATURE_CHALLENGE_TTL_MS, BINDING_SIGNATURE_POOL_CAPACITY,
};
use crate::traits::log_trace::RustFileId;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::{log_e, log_i, p, Vec};
pub(crate) const FILE_ID: u16 = RustFileId::BindingChallengePool as u16;

struct BindingChallengeEntry {
    challenge: [u8; BINDING_SIGNATURE_CHALLENGE_LEN],
    added_at_ms: u64,
}

impl BindingChallengeEntry {
    fn is_live(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.added_at_ms) < BINDING_SIGNATURE_CHALLENGE_TTL_MS
    }
}

pub struct BindingChallengePool {
    entries: Vec<BindingChallengeEntry>,
}

impl BindingChallengePool {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn insert(&mut self, challenge: &[u8], now_ms: u64) -> Result<(), ErrorCode> {
        if challenge.len() != BINDING_SIGNATURE_CHALLENGE_LEN {
            log_e!("challenge length mismatch: expected {}", BINDING_SIGNATURE_CHALLENGE_LEN);
            return Err(ErrorCode::BadParam);
        }
        self.sweep_expired(now_ms);
        if self.entries.len() >= BINDING_SIGNATURE_POOL_CAPACITY {
            if let Some((index, _)) = self.entries.iter().enumerate().min_by_key(|(_, entry)| entry.added_at_ms) {
                self.entries.remove(index);
            }
            log_i!("binding challenge pool full, evict oldest, pool size:{}", self.entries.len());
        }
        self.entries.push(BindingChallengeEntry {
            challenge: challenge.try_into().map_err(|_| ErrorCode::BadParam)?,
            added_at_ms: now_ms,
        });
        Ok(())
    }

    pub fn validate(&self, challenge: &[u8], now_ms: u64) -> bool {
        let Some(entry) = self.entries.iter().find(|entry| entry.challenge.as_slice() == challenge) else {
            return false;
        };
        entry.is_live(now_ms)
    }

    pub fn purge(&mut self, challenge: &[u8]) {
        self.entries.retain(|entry| entry.challenge.as_slice() != challenge);
    }

    pub fn sweep_expired(&mut self, now_ms: u64) {
        self.entries.retain(|entry| entry.is_live(now_ms));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

static mut POOL: Option<BindingChallengePool> = None;

fn pool_mut() -> &'static mut BindingChallengePool {
    unsafe {
        if POOL.is_none() {
            POOL = Some(BindingChallengePool::new());
        }
        POOL.as_mut().unwrap()
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub fn reset() {
    unsafe {
        POOL = Some(BindingChallengePool::new());
    }
}

pub fn insert(challenge: &[u8]) -> Result<(), ErrorCode> {
    let now_ms = TimeKeeperRegistry::get().get_system_time().map_err(|e| p!(e))?;
    log_i!("insert binding signature challenge, pool size:{}", pool_mut().len());
    pool_mut().insert(challenge, now_ms)
}

pub fn validate(challenge: &[u8]) -> Result<bool, ErrorCode> {
    let now_ms = TimeKeeperRegistry::get().get_system_time().map_err(|e| p!(e))?;
    Ok(pool_mut().validate(challenge, now_ms))
}

pub fn purge(challenge: &[u8]) {
    log_i!("purge binding signature challenge, pool size:{}", pool_mut().len());
    pool_mut().purge(challenge);
}
