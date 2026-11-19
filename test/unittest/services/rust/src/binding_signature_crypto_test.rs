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
const FILE_ID: u16 = TestFileId::BindingSignatureCryptoTest as u16;

// any byte length within the DER upper bound passes the length checks under test
const DER_SIGNATURE_FIXTURE_LEN: usize = 70;

use crate::common::constants::{
    ErrorCode, PROTOCOL_VERSION_1, PROTOCOL_VERSION_2, P256, BINDING_SIGNATURE_CHALLENGE_LEN,
    BINDING_SIGNATURE_VALUE_MAX_LEN, BINDING_SIGNATURE_PRI_KEY_LEN, BINDING_SIGNATURE_PUB_KEY_LEN,
};
use crate::jobs::binding_challenge_pool;
use crate::jobs::binding_signature_crypto::{
    check_pub_key, generate_challenge, generate_key_pair, host_binding_sign, pri_key_len, pub_key_len,
    verify_binding_signature,
};
use crate::log_i;
use crate::traits::companion_device_db_manager::{CompanionDeviceDbManagerRegistry, MockCompanionDeviceDbManager};
use crate::traits::crypto_engine::{CryptoEngineRegistry, MockCryptoEngine};
use crate::traits::db_manager::{
    CompanionDeviceSignPriKey, DeviceKey, HostBinding, HostBindingSignaturePubKey, UserInfo, UserKey,
};
use crate::traits::host_binding_db_manager::{HostBindingDbManagerRegistry, MockHostBindingDbManager};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|buf| {
        for (i, item) in buf.iter_mut().enumerate() {
            *item = i as u8;
        }
        Ok(())
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_companion_device_db(alg_id: u16) {
    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_read_device_binding_signature_key().returning(move || {
        Ok(CompanionDeviceSignPriKey { alg_id, pri_key: vec![0x08u8; BINDING_SIGNATURE_PRI_KEY_LEN] })
    });
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));
}

fn create_mock_binding(binding_id: i32, enrolled_protocol_id: u16) -> HostBinding {
    HostBinding {
        device_key: DeviceKey {
            device_id: String::from("host_device"),
            device_id_type: 1,
            user_id: 100,
            sub_profile_id: 0,
        },
        binding_id,
        user_info: UserInfo { user_key: UserKey { user_id: 100, sub_profile_id: 0 }, user_type: 0 },
        binding_time: 123456,
        last_used_time: 123456,
        enrolled_protocol_id,
        secure_protocol_id: 1,
    }
}

fn mock_set_gate_db(enrolled_protocol_id: u16, key_result: Option<HostBindingSignaturePubKey>) {
    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager
        .expect_get_device_by_binding_id()
        .returning(move || Ok(create_mock_binding(1, enrolled_protocol_id)));
    match key_result {
        Some(key) => mock_host_binding_db_manager
            .expect_read_binding_signature_key()
            .returning(move || Ok(key.clone())),
        None => mock_host_binding_db_manager
            .expect_read_binding_signature_key()
            .returning(|| Err(ErrorCode::NotFound)),
    }
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));
}

fn mock_set_static_time() {
    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_system_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));
}

fn mock_p256_verify_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_p256_ecdsa_verify().returning(|_data, _sign| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

// Challenge issuance fills the full challenge length from the engine's secure random.
#[test]
fn generate_challenge_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("generate_challenge_test_success start");

    mock_set_crypto_engine();
    let result = generate_challenge();
    assert!(result.is_ok());
    let challenge = result.unwrap();
    assert_eq!(challenge.len(), BINDING_SIGNATURE_CHALLENGE_LEN);
    assert_eq!(challenge, (0u8..BINDING_SIGNATURE_CHALLENGE_LEN as u8).collect::<Vec<u8>>());
}

// A failing CSPRNG fails challenge issuance with the engine's error.
#[test]
fn generate_challenge_test_random_fail() {
    let _guard = ut_registry_guard!();
    log_i!("generate_challenge_test_random_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let result = generate_challenge();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

// The signed object is the 32B challenge itself: exactly the challenge bytes reach the engine.
#[test]
fn host_binding_signature_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_binding_signature_test_success start");

    mock_set_companion_device_db(P256);
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_p256_ecdsa_sign()
        .returning(|_pri_key, data| Ok(data.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let challenge = vec![0x11u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    let result = host_binding_sign(1, &challenge);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), challenge);
}

// A challenge of any other length is rejected before the engine is touched.
#[test]
fn host_binding_signature_test_challenge_len_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_binding_signature_test_challenge_len_mismatch start");

    mock_set_companion_device_db(P256);
    // No p256_ecdsa_sign expectation: reaching the engine would panic the test.
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let challenge = vec![0u8; BINDING_SIGNATURE_CHALLENGE_LEN - 1];
    let result = host_binding_sign(1, &challenge);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

// An algorithm other than the persisted P-256 id is rejected before the engine is touched.
#[test]
fn host_binding_signature_test_unsupported_alg() {
    let _guard = ut_registry_guard!();
    log_i!("host_binding_signature_test_unsupported_alg start");

    mock_set_companion_device_db(P256 + 1);
    // No p256_ecdsa_sign expectation: reaching the engine would panic the test.
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let challenge = vec![0x11u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    let result = host_binding_sign(1, &challenge);
    assert_eq!(result, Err(ErrorCode::AlgorithmNegotiationFailed));
}

// key⇔proof decision table: V2 ⇔ proof present, both or neither.
#[test]
fn verify_binding_signature_test_v2_with_proof() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_v2_with_proof start");

    mock_set_gate_db(
        PROTOCOL_VERSION_2,
        Some(HostBindingSignaturePubKey { alg_id: P256, pub_key: vec![0x04u8; BINDING_SIGNATURE_PUB_KEY_LEN] }),
    );
    mock_set_static_time();
    mock_p256_verify_engine();

    let challenge = vec![0x33u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    assert!(binding_challenge_pool::insert(&challenge).is_ok());
    let sign = vec![0x44u8; DER_SIGNATURE_FIXTURE_LEN];
    let result = verify_binding_signature(1, &challenge, &sign);
    assert!(result.is_ok());
    // Validation does not consume: the same proof validates for every protected message on the
    // connection.
    let result = verify_binding_signature(1, &challenge, &sign);
    assert!(result.is_ok());
}

// A proof whose challenge is not the issued value is rejected without consuming the entry
// for the issued one.
#[test]
fn verify_binding_signature_test_wrong_challenge_rejected() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_wrong_challenge_rejected start");

    mock_set_gate_db(
        PROTOCOL_VERSION_2,
        Some(HostBindingSignaturePubKey { alg_id: P256, pub_key: vec![0x04u8; BINDING_SIGNATURE_PUB_KEY_LEN] }),
    );
    mock_set_static_time();
    mock_p256_verify_engine();

    let challenge = vec![0x33u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    assert!(binding_challenge_pool::insert(&challenge).is_ok());
    let sign = vec![0x44u8; DER_SIGNATURE_FIXTURE_LEN];

    let wrong = vec![0x55u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    let result = verify_binding_signature(1, &wrong, &sign);
    assert_eq!(result, Err(ErrorCode::BindingSignatureVerifyFailed));
    // the pool entry survives the mismatched attempt for the issued value
    let result = verify_binding_signature(1, &challenge, &sign);
    assert!(result.is_ok());
}

// A V2 binding must carry a proof: verifying with neither challenge nor signature is rejected.
#[test]
fn verify_binding_signature_test_v2_without_proof() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_v2_without_proof start");

    // No read_binding_signature_key expectation: reaching the key would panic the test.
    mock_set_gate_db(PROTOCOL_VERSION_2, None);

    let result = verify_binding_signature(1, &[], &[]);
    assert_eq!(result, Err(ErrorCode::BindingSignatureVerifyFailed));
}

// A V1 binding carries no proof material and verifies as a no-op.
#[test]
fn verify_binding_signature_test_v1_without_proof() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_v1_without_proof start");

    // No read_binding_signature_key expectation: reaching the key would panic the test.
    mock_set_gate_db(PROTOCOL_VERSION_1, None);

    let result = verify_binding_signature(1, &[], &[]);
    assert!(result.is_ok());
}

// A V1 binding must not carry proof material: any proof on a V1 row is rejected.
#[test]
fn verify_binding_signature_test_v1_with_proof() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_v1_with_proof start");

    // No read_binding_signature_key expectation: reaching the key would panic the test.
    mock_set_gate_db(PROTOCOL_VERSION_1, None);

    let challenge = vec![0x33u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    let sign = vec![0x44u8; DER_SIGNATURE_FIXTURE_LEN];
    let result = verify_binding_signature(1, &challenge, &sign);
    assert_eq!(result, Err(ErrorCode::BindingSignatureVerifyFailed));
}

// Exactly one of challenge/signature empty is malformed: rejected in every combination,
// without touching the pool or the key row.
#[test]
fn verify_binding_signature_test_partial_proof() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_partial_proof start");

    mock_set_gate_db(PROTOCOL_VERSION_2, None);
    let sign = vec![0x44u8; DER_SIGNATURE_FIXTURE_LEN];
    let result = verify_binding_signature(1, &[], &sign);
    assert_eq!(result, Err(ErrorCode::BindingSignatureVerifyFailed));

    mock_set_gate_db(PROTOCOL_VERSION_1, None);
    let result = verify_binding_signature(1, &[], &sign);
    assert_eq!(result, Err(ErrorCode::BindingSignatureVerifyFailed));
}

// A proof whose challenge was never issued is rejected.
#[test]
fn verify_binding_signature_test_challenge_not_in_pool() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_challenge_not_in_pool start");

    // No read_binding_signature_key expectation: reaching the key would panic the test.
    mock_set_gate_db(PROTOCOL_VERSION_2, None);
    mock_set_static_time();

    let challenge = vec![0x33u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    let sign = vec![0x44u8; DER_SIGNATURE_FIXTURE_LEN];
    let result = verify_binding_signature(1, &challenge, &sign);
    assert_eq!(result, Err(ErrorCode::BindingSignatureVerifyFailed));
}

// V2 with a missing key row is corrupted material: rejected, never downgraded to V1 semantics.
#[test]
fn verify_binding_signature_test_v2_key_row_missing() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_v2_key_row_missing start");

    // No p256_ecdsa_verify expectation: reaching the engine would panic the test.
    mock_set_gate_db(PROTOCOL_VERSION_2, None);
    mock_set_static_time();

    let challenge = vec![0x33u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    assert!(binding_challenge_pool::insert(&challenge).is_ok());
    let sign = vec![0x44u8; DER_SIGNATURE_FIXTURE_LEN];
    let result = verify_binding_signature(1, &challenge, &sign);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

// Signatures are variable length: empty input and anything above the 72-byte
// upper bound must be rejected before the crypto engine is called.
#[test]
fn verify_binding_signature_test_sign_length_invalid() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_sign_length_invalid start");

    mock_set_gate_db(
        PROTOCOL_VERSION_2,
        Some(HostBindingSignaturePubKey { alg_id: P256, pub_key: vec![0x04u8; BINDING_SIGNATURE_PUB_KEY_LEN] }),
    );
    mock_set_static_time();
    // No p256_ecdsa_verify expectation: reaching the engine would panic the test.
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let challenge = vec![0x33u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    assert!(binding_challenge_pool::insert(&challenge).is_ok());
    let result = verify_binding_signature(1, &challenge, &[]);
    assert_eq!(result, Err(ErrorCode::BindingSignatureVerifyFailed));

    let sign = vec![0x44u8; BINDING_SIGNATURE_VALUE_MAX_LEN + 1];
    let result = verify_binding_signature(1, &challenge, &sign);
    assert_eq!(result, Err(ErrorCode::BindingSignatureVerifyFailed));
}

// An algorithm other than the persisted P-256 id is rejected before the engine is touched.
#[test]
fn verify_binding_signature_test_unsupported_alg() {
    let _guard = ut_registry_guard!();
    log_i!("verify_binding_signature_test_unsupported_alg start");

    mock_set_gate_db(
        PROTOCOL_VERSION_2,
        Some(HostBindingSignaturePubKey { alg_id: P256 + 1, pub_key: vec![0x04u8; BINDING_SIGNATURE_PUB_KEY_LEN] }),
    );
    mock_set_static_time();
    // No p256_ecdsa_verify expectation: reaching the engine would panic the test.
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let challenge = vec![0x33u8; BINDING_SIGNATURE_CHALLENGE_LEN];
    assert!(binding_challenge_pool::insert(&challenge).is_ok());
    let sign = vec![0x44u8; DER_SIGNATURE_FIXTURE_LEN];
    let result = verify_binding_signature(1, &challenge, &sign);
    assert_eq!(result, Err(ErrorCode::AlgorithmNegotiationFailed));
}

// The dispatch layer rejects algorithms outside the supported table before any engine call.
#[test]
fn binding_signature_dispatch_test_unsupported_alg() {
    let _guard = ut_registry_guard!();
    log_i!("binding_signature_dispatch_test_unsupported_alg start");

    // No expectation: any engine call would panic the test.
    CryptoEngineRegistry::set(Box::new(MockCryptoEngine::new()));

    let bogus = P256 + 1;
    assert_eq!(check_pub_key(bogus, &[0x04u8; BINDING_SIGNATURE_PUB_KEY_LEN]), Err(ErrorCode::AlgorithmNegotiationFailed));
    assert_eq!(pub_key_len(bogus), Err(ErrorCode::AlgorithmNegotiationFailed));
    assert_eq!(pri_key_len(bogus), Err(ErrorCode::AlgorithmNegotiationFailed));
    assert_eq!(generate_key_pair(bogus), Err(ErrorCode::AlgorithmNegotiationFailed));
}

// Pub key format checking is an engine capability: check_pub_key delegates by algorithm id
// and passes the engine's verdict through.
#[test]
fn binding_signature_dispatch_test_check_pub_key_delegates() {
    let _guard = ut_registry_guard!();
    log_i!("binding_signature_dispatch_test_check_pub_key_delegates start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_p256_check_pub_key().returning(|pub_key| {
        if pub_key.len() == BINDING_SIGNATURE_PUB_KEY_LEN && pub_key.first() == Some(&0x04) {
            Ok(())
        } else {
            Err(ErrorCode::GeneralError)
        }
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    assert!(check_pub_key(P256, &[0x04u8; BINDING_SIGNATURE_PUB_KEY_LEN]).is_ok());
    assert_eq!(check_pub_key(P256, &[0x07u8; 5]), Err(ErrorCode::GeneralError));
}
