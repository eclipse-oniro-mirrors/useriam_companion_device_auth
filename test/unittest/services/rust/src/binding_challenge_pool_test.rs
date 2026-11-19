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

use crate::traits::log_trace::TestFileId;
const FILE_ID: u16 = TestFileId::BindingChallengePoolTest as u16;

use crate::common::constants::{
    ErrorCode, BINDING_SIGNATURE_CHALLENGE_LEN, BINDING_SIGNATURE_CHALLENGE_TTL_MS, BINDING_SIGNATURE_POOL_CAPACITY,
};
use crate::jobs::binding_challenge_pool::{self, BindingChallengePool};
use crate::log_i;
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;

fn challenge_of(byte: u8) -> Vec<u8> {
    vec![byte; BINDING_SIGNATURE_CHALLENGE_LEN]
}

// An inserted challenge validates; an unknown value does not match and the entry survives the
// mismatch.
#[test]
fn pool_insert_then_validate_by_value() {
    let _guard = ut_registry_guard!();
    log_i!("pool_insert_then_validate_by_value start");

    let mut pool = BindingChallengePool::new();
    assert!(pool.insert(&challenge_of(1), 1000).is_ok());
    assert!(pool.validate(&challenge_of(1), 1000));
    assert!(!pool.validate(&challenge_of(2), 1000));
    assert!(pool.validate(&challenge_of(1), 1000));
}

// Validation is reusable within the issuance window but never extends it: the entry stays
// valid until insert-time+TTL no matter how often it validates, so the TTL is an absolute
// cap on the replay window of a captured proof.
#[test]
fn pool_validate_reusable_without_ttl_slide() {
    let _guard = ut_registry_guard!();
    log_i!("pool_validate_reusable_without_ttl_slide start");

    let mut pool = BindingChallengePool::new();
    assert!(pool.insert(&challenge_of(1), 1000).is_ok());
    assert!(pool.validate(&challenge_of(1), 1000));
    assert!(pool.validate(&challenge_of(1), 1000));
    // repeated validations do not slide the original expiry from issuance
    let last_valid = 1000 + BINDING_SIGNATURE_CHALLENGE_TTL_MS - 1;
    assert!(pool.validate(&challenge_of(1), last_valid));
    assert!(!pool.validate(&challenge_of(1), last_valid + 1));
}

// Purge drops the entry for its challenge value; purging an unknown value is a no-op.
#[test]
fn pool_purge_drops_entry() {
    let _guard = ut_registry_guard!();
    log_i!("pool_purge_drops_entry start");

    let mut pool = BindingChallengePool::new();
    assert!(pool.insert(&challenge_of(0), 1000).is_ok());
    pool.purge(&challenge_of(0));
    assert!(!pool.validate(&challenge_of(0), 1000));

    pool.purge(&challenge_of(0));
    pool.purge(&[]);
}

// A full pool evicts the entry with the earliest added time instead of rejecting the new
// issuance: the failure lands on the oldest outstanding round, never on the new one.
#[test]
fn pool_full_evicts_oldest_keeps_rest() {
    let _guard = ut_registry_guard!();
    log_i!("pool_full_evicts_oldest_keeps_rest start");

    let mut pool = BindingChallengePool::new();
    for i in 0..BINDING_SIGNATURE_POOL_CAPACITY {
        assert!(pool.insert(&challenge_of(i as u8), 1000).is_ok());
    }
    let next = BINDING_SIGNATURE_POOL_CAPACITY as u8;
    assert!(pool.insert(&challenge_of(next), 2000).is_ok());
    assert!(!pool.validate(&challenge_of(0), 2000));
    assert!(pool.validate(&challenge_of(1), 2000));
    assert!(pool.validate(&challenge_of(next), 2000));
}

// Eviction picks the earliest added_at_ms, not the earliest pushed position.
#[test]
fn pool_evicts_by_added_time_not_position() {
    let _guard = ut_registry_guard!();
    log_i!("pool_evicts_by_added_time_not_position start");

    let mut pool = BindingChallengePool::new();
    for i in 0..BINDING_SIGNATURE_POOL_CAPACITY {
        let now_ms = if i == 0 { 2000 } else { 1000 + i as u64 };
        assert!(pool.insert(&challenge_of(i as u8), now_ms).is_ok());
    }
    assert!(pool.insert(&challenge_of(BINDING_SIGNATURE_POOL_CAPACITY as u8), 3000).is_ok());
    assert!(!pool.validate(&challenge_of(1), 3000));
    assert!(pool.validate(&challenge_of(0), 3000));
}

// A sweep at a time when one entry has expired keeps the other alive; validation of the
// swept entry fails afterwards.
#[test]
fn pool_sweep_expired_on_issue() {
    let _guard = ut_registry_guard!();
    log_i!("pool_sweep_expired_on_issue start");

    let mut pool = BindingChallengePool::new();
    assert!(pool.insert(&challenge_of(1), 1000).is_ok());
    assert!(pool.insert(&challenge_of(2), 2000).is_ok());
    pool.sweep_expired(1000 + BINDING_SIGNATURE_CHALLENGE_TTL_MS);
    assert!(!pool.validate(&challenge_of(1), 1000 + BINDING_SIGNATURE_CHALLENGE_TTL_MS));
    assert!(pool.validate(&challenge_of(2), 2000 + BINDING_SIGNATURE_CHALLENGE_TTL_MS - 1));
}

// Only full-length challenges enter the pool: a short value is rejected before the pool
// state changes.
#[test]
fn pool_insert_rejects_bad_challenge_len() {
    let _guard = ut_registry_guard!();
    log_i!("pool_insert_rejects_bad_challenge_len start");

    let mut pool = BindingChallengePool::new();
    assert_eq!(pool.insert(&challenge_of(1)[..31], 1000), Err(ErrorCode::BadParam));
    assert!(pool.insert(&challenge_of(1), 1000).is_ok());
}

// Module-level wrappers: insert/validate/purge through the global pool and the time keeper.
#[test]
fn pool_module_round_trip() {
    let _guard = ut_registry_guard!();
    log_i!("pool_module_round_trip start");

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_system_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let challenge = challenge_of(7);
    assert!(binding_challenge_pool::insert(&challenge).is_ok());
    // validation is reusable: the same proof material validates for every message from the host
    assert_eq!(binding_challenge_pool::validate(&challenge), Ok(true));
    assert_eq!(binding_challenge_pool::validate(&challenge), Ok(true));

    binding_challenge_pool::purge(&challenge);
    assert_eq!(binding_challenge_pool::validate(&challenge), Ok(false));
}
