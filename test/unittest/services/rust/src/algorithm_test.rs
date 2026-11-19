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

use crate::common::algorithm::{
    get_supported_algorithms, select_optional_algorithm, validate_optional_algorithm_supported,
    validate_selected_algorithms_supported, validate_sk_algorithms, SelectedAlgorithms,
};
use crate::common::constants::{
    AeadAlgoType, P256, ErrorCode, KdfAlgoType, MacAlgoType, SUPPORTED_BINDING_SIGNATURE_ALGORITHMS,
};

// A session algorithm of 0 (or any value outside the supported list) means a corrupt
// SK row and must fail with 20013 instead of reaching the crypto dispatch layer.
#[test]
fn validate_sk_algorithms_test_unsupported_rejected_for_each_role() {
    let kdf = KdfAlgoType::HkdfSha256 as u16;
    let aead = AeadAlgoType::Aes256Gcm as u16;
    let mac = MacAlgoType::HmacSha256 as u16;
    assert_eq!(validate_sk_algorithms(kdf, aead, mac), Ok(()));

    let bad_cases = [(0, aead, mac), (kdf, 0, mac), (kdf, aead, 0), (2, aead, mac), (kdf, 2, mac), (kdf, aead, 2)];
    for (bad_kdf, bad_aead, bad_mac) in bad_cases {
        assert_eq!(
            validate_sk_algorithms(bad_kdf, bad_aead, bad_mac),
            Err(ErrorCode::SecureProtocolNotSupported)
        );
    }
}

// Generic negotiation mechanism for an optional algorithm axis (binding signature is the
// current instantiation). An empty offered list means the axis is disabled (None). Any other
// offer is intersected with the shared priority table: unknown values are filtered, the
// table's priority order decides, and an empty intersection fails — no default.
#[test]
fn select_optional_algorithm_test() {
    let prioritized = [7, 5];
    assert_eq!(select_optional_algorithm("axis", &prioritized, &[]), Ok(None));
    // Priority order comes from the shared table, not the offer order.
    assert_eq!(select_optional_algorithm("axis", &prioritized, &[5, 7]), Ok(Some(7)));
    assert_eq!(select_optional_algorithm("axis", &prioritized, &[9, 5]), Ok(Some(5)));
    assert_eq!(
        select_optional_algorithm("axis", &prioritized, &[9]),
        Err(ErrorCode::AlgorithmNegotiationFailed)
    );
    // The real binding-signature axis keeps selecting over the shared table.
    assert_eq!(
        select_optional_algorithm(
            "binding signature",
            SUPPORTED_BINDING_SIGNATURE_ALGORITHMS,
            &[P256]
        ),
        Ok(Some(P256))
    );
}

// None is the only absent state an optional axis accepts (axis disabled). A carried value —
// including an explicit wire 0 — must be a member of the shared support table.
#[test]
fn validate_optional_algorithm_supported_test() {
    assert_eq!(validate_optional_algorithm_supported("axis", &[7, 5], None), Ok(()));
    assert_eq!(validate_optional_algorithm_supported("axis", &[7, 5], Some(5)), Ok(()));
    assert_eq!(
        validate_optional_algorithm_supported("axis", &[7, 5], Some(9)),
        Err(ErrorCode::AlgorithmNegotiationFailed)
    );
    assert_eq!(
        validate_optional_algorithm_supported("axis", &[7, 5], Some(0)),
        Err(ErrorCode::AlgorithmNegotiationFailed)
    );
}

// None is the only absent state the generic validator lets through (V1, unsigned binding).
// A carried value — including an explicit wire 0 — must be a member of the shared table.
#[test]
fn validate_selected_algorithms_supported_binding_signature_test() {
    let supported = get_supported_algorithms();
    let make = |binding_signature_algorithm: Option<u16>| SelectedAlgorithms {
        ka_algorithm: 1,
        kdf_algorithm: 1,
        aead_algorithm: 1,
        mac_algorithm: 1,
        binding_signature_algorithm,
    };
    assert_eq!(
        validate_selected_algorithms_supported(&make(Some(P256)), &supported),
        Ok(())
    );
    assert_eq!(validate_selected_algorithms_supported(&make(None), &supported), Ok(()));
    assert_eq!(
        validate_selected_algorithms_supported(&make(Some(0)), &supported),
        Err(ErrorCode::AlgorithmNegotiationFailed)
    );
    assert_eq!(
        validate_selected_algorithms_supported(&make(Some(P256 + 1)), &supported),
        Err(ErrorCode::AlgorithmNegotiationFailed)
    );
}
