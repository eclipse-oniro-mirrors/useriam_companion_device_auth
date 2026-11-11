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
    AeadAlgoType, ErrorCode, KaAlgoType, KdfAlgoType, MacAlgoType, SUPPORTED_AEAD_ALGORITHMS,
    SUPPORTED_KA_ALGORITHMS, SUPPORTED_KDF_ALGORITHMS, SUPPORTED_MAC_ALGORITHMS,
    intersect_lists_in_reference_order,
};
use crate::log_e;
use crate::traits::log_trace::RustFileId;
use crate::Vec;
pub(crate) const FILE_ID: u16 = RustFileId::Algorithm as u16;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CryptoAlgorithms {
    pub ka_algorithms: Vec<u16>,
    pub kdf_algorithms: Vec<u16>,
    pub aead_algorithms: Vec<u16>,
    pub mac_algorithms: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelectedAlgorithms {
    pub ka_algorithm: u16,
    pub kdf_algorithm: u16,
    pub aead_algorithm: u16,
    pub mac_algorithm: u16,
}

pub fn validate_selected_algorithms(algorithms: &SelectedAlgorithms) -> core::result::Result<(), ErrorCode> {
    let checks = [
        (algorithms.ka_algorithm, SUPPORTED_KA_ALGORITHMS),
        (algorithms.kdf_algorithm, SUPPORTED_KDF_ALGORITHMS),
        (algorithms.aead_algorithm, SUPPORTED_AEAD_ALGORITHMS),
        (algorithms.mac_algorithm, SUPPORTED_MAC_ALGORITHMS),
    ];
    for (algorithm, supported_list) in checks {
        if !supported_list.contains(&algorithm) {
            log_e!(
                "persisted selected algorithm {} is not in the supported list {:?}, ka:{}, kdf:{}, aead:{}, mac:{}",
                algorithm,
                supported_list,
                algorithms.ka_algorithm,
                algorithms.kdf_algorithm,
                algorithms.aead_algorithm,
                algorithms.mac_algorithm
            );
            return Err(ErrorCode::SecureProtocolNotSupported);
        }
    }
    Ok(())
}

pub fn get_supported_algorithms() -> CryptoAlgorithms {
    CryptoAlgorithms {
        ka_algorithms: SUPPORTED_KA_ALGORITHMS.to_vec(),
        kdf_algorithms: SUPPORTED_KDF_ALGORITHMS.to_vec(),
        aead_algorithms: SUPPORTED_AEAD_ALGORITHMS.to_vec(),
        mac_algorithms: SUPPORTED_MAC_ALGORITHMS.to_vec(),
    }
}

pub fn intersect_algorithms_in_reference_order(
    reference: &CryptoAlgorithms,
    candidate: &CryptoAlgorithms,
) -> CryptoAlgorithms {
    CryptoAlgorithms {
        ka_algorithms: intersect_lists_in_reference_order(&reference.ka_algorithms, &candidate.ka_algorithms),
        kdf_algorithms: intersect_lists_in_reference_order(&reference.kdf_algorithms, &candidate.kdf_algorithms),
        aead_algorithms: intersect_lists_in_reference_order(&reference.aead_algorithms, &candidate.aead_algorithms),
        mac_algorithms: intersect_lists_in_reference_order(&reference.mac_algorithms, &candidate.mac_algorithms),
    }
}

pub fn select_algorithms_by_priority(
    priority: &CryptoAlgorithms,
    candidates: &CryptoAlgorithms,
) -> Result<SelectedAlgorithms, ErrorCode> {
    Ok(SelectedAlgorithms {
        ka_algorithm: select_algorithm_by_priority("ka", &priority.ka_algorithms, &candidates.ka_algorithms)?,
        kdf_algorithm: select_algorithm_by_priority("kdf", &priority.kdf_algorithms, &candidates.kdf_algorithms)?,
        aead_algorithm: select_algorithm_by_priority(
            "aead",
            &priority.aead_algorithms,
            &candidates.aead_algorithms,
        )?,
        mac_algorithm: select_algorithm_by_priority("mac", &priority.mac_algorithms, &candidates.mac_algorithms)?,
    })
}

fn select_algorithm_by_priority(role: &str, prioritized: &[u16], candidates: &[u16]) -> Result<u16, ErrorCode> {
    for algorithm in prioritized {
        if candidates.contains(algorithm) {
            return Ok(*algorithm);
        }
    }
    log_e!("no supported {} algorithm in candidates: {:?}, prioritized: {:?}", role, candidates, prioritized);
    Err(ErrorCode::AlgorithmNegotiationFailed)
}

pub fn validate_selected_algorithms_supported(
    selected: &SelectedAlgorithms,
    supported: &CryptoAlgorithms,
) -> Result<(), ErrorCode> {
    let checks = [
        (selected.ka_algorithm, &supported.ka_algorithms, "ka"),
        (selected.kdf_algorithm, &supported.kdf_algorithms, "kdf"),
        (selected.aead_algorithm, &supported.aead_algorithms, "aead"),
        (selected.mac_algorithm, &supported.mac_algorithms, "mac"),
    ];
    for (algorithm, supported_list, role) in checks {
        if !supported_list.contains(&algorithm) {
            log_e!("selected {} algorithm {} is not in the supported list {:?}", role, algorithm, supported_list);
            return Err(ErrorCode::AlgorithmNegotiationFailed);
        }
    }
    Ok(())
}
