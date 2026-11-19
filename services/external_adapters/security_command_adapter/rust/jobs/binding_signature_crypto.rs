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
    ErrorCode, P256, BINDING_SIGNATURE_CHALLENGE_LEN, BINDING_SIGNATURE_PRI_KEY_LEN,
    BINDING_SIGNATURE_PUB_KEY_LEN, BINDING_SIGNATURE_VALUE_MAX_LEN, PROTOCOL_VERSION_2, validate_protocol_id,
};
use crate::jobs::binding_challenge_pool;
use crate::traits::companion_device_db_manager::CompanionDeviceDbManagerRegistry;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair};
use crate::traits::host_binding_db_manager::HostBindingDbManagerRegistry;
use crate::traits::log_trace::RustFileId;
use crate::{log_e, log_i, p};
pub(crate) const FILE_ID: u16 = RustFileId::BindingSignatureCrypto as u16;

fn check_challenge_len(challenge: &[u8]) -> Result<(), ErrorCode> {
    if challenge.len() != BINDING_SIGNATURE_CHALLENGE_LEN {
        log_e!("challenge length mismatch: expected {}", BINDING_SIGNATURE_CHALLENGE_LEN);
        return Err(ErrorCode::BadParam);
    }
    Ok(())
}

pub fn check_pub_key(alg_id: u16, pub_key: &[u8]) -> Result<(), ErrorCode> {
    match alg_id {
        P256 => CryptoEngineRegistry::get().p256_check_pub_key(pub_key).map_err(|e| p!(e)),
        _ => {
            log_e!("unsupported binding signature alg: {}", alg_id);
            Err(ErrorCode::AlgorithmNegotiationFailed)
        },
    }
}

pub fn generate_key_pair(alg_id: u16) -> Result<KeyPair, ErrorCode> {
    match alg_id {
        P256 => {
            CryptoEngineRegistry::get().generate_p256_key_pair().map_err(|e| p!(e))
        },
        _ => {
            log_e!("unsupported binding signature alg: {}", alg_id);
            Err(ErrorCode::AlgorithmNegotiationFailed)
        },
    }
}

fn sign(alg_id: u16, pri_key: &[u8], data: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
    match alg_id {
        P256 => CryptoEngineRegistry::get().p256_ecdsa_sign(pri_key, data).map_err(|e| p!(e)),
        _ => {
            log_e!("unsupported binding signature alg: {}", alg_id);
            Err(ErrorCode::AlgorithmNegotiationFailed)
        },
    }
}

fn verify(alg_id: u16, pub_key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), ErrorCode> {
    match alg_id {
        P256 => CryptoEngineRegistry::get()
            .p256_ecdsa_verify(pub_key, data, signature)
            .map_err(|_| ErrorCode::BindingSignatureVerifyFailed),
        _ => {
            log_e!("unsupported binding signature alg: {}", alg_id);
            Err(ErrorCode::AlgorithmNegotiationFailed)
        },
    }
}

pub fn pub_key_len(alg_id: u16) -> Result<usize, ErrorCode> {
    match alg_id {
        P256 => Ok(BINDING_SIGNATURE_PUB_KEY_LEN),
        _ => {
            log_e!("unsupported binding signature alg: {}", alg_id);
            Err(ErrorCode::AlgorithmNegotiationFailed)
        },
    }
}

pub fn pri_key_len(alg_id: u16) -> Result<usize, ErrorCode> {
    match alg_id {
        P256 => Ok(BINDING_SIGNATURE_PRI_KEY_LEN),
        _ => {
            log_e!("unsupported binding signature alg: {}", alg_id);
            Err(ErrorCode::AlgorithmNegotiationFailed)
        },
    }
}

pub fn host_binding_sign(template_id: u64, challenge: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
    log_i!("host_binding_sign start, template_id:{:016x}", template_id);
    check_challenge_len(challenge)?;
    let binding_signature_key =
        CompanionDeviceDbManagerRegistry::get().read_device_binding_signature_key(template_id).map_err(|e| p!(e))?;
    sign(binding_signature_key.alg_id, &binding_signature_key.pri_key, challenge)
}

pub fn verify_binding_signature(
    binding_id: i32,
    challenge: &[u8],
    signature: &[u8],
) -> Result<(), ErrorCode> {
    log_i!("verify_binding_signature start, binding_id:{:04x}", binding_id as u16);
    let device_info =
        HostBindingDbManagerRegistry::get().get_device_by_binding_id(binding_id).map_err(|e| p!(e))?;
    validate_protocol_id(device_info.enrolled_protocol_id)?;
    let is_v2 = device_info.enrolled_protocol_id == PROTOCOL_VERSION_2;
    let proof_present = !challenge.is_empty() || !signature.is_empty();
    match (is_v2, proof_present) {
        (false, false) => Ok(()),
        (false, true) => {
            log_e!("v1 binding must not carry a binding signature proof");
            Err(ErrorCode::BindingSignatureVerifyFailed)
        },
        (true, false) => {
            log_e!("binding signature proof missing");
            Err(ErrorCode::BindingSignatureVerifyFailed)
        },
        (true, true) => {
            if challenge.is_empty() || signature.is_empty() {
                log_e!(
                    "binding signature proof incomplete, challenge len:{}, signature len:{}",
                    challenge.len(),
                    signature.len()
                );
                return Err(ErrorCode::BindingSignatureVerifyFailed);
            }
            if !binding_challenge_pool::validate(challenge).map_err(|e| p!(e))? {
                log_e!("binding signature challenge not issued or expired");
                return Err(ErrorCode::BindingSignatureVerifyFailed);
            }
            verify_binding_signature_internal(binding_id, challenge, signature)
        },
    }
}

fn verify_binding_signature_internal(binding_id: i32, challenge: &[u8], signature: &[u8]) -> Result<(), ErrorCode> {
    let binding_signature_key =
        HostBindingDbManagerRegistry::get().read_binding_signature_key(binding_id).map_err(|e| p!(e))?;
    if signature.len() > BINDING_SIGNATURE_VALUE_MAX_LEN {
        log_e!("binding signature length invalid: {}", signature.len());
        return Err(ErrorCode::BindingSignatureVerifyFailed);
    }

    verify(binding_signature_key.alg_id, &binding_signature_key.pub_key, challenge, signature)
}

pub fn generate_challenge() -> Result<crate::Vec<u8>, ErrorCode> {
    let mut challenge = crate::Vec::new();
    challenge.resize(BINDING_SIGNATURE_CHALLENGE_LEN, 0u8);
    CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|e| p!(e))?;
    Ok(challenge)
}
