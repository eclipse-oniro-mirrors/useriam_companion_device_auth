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
use crate::common::Udid;
use crate::log_i;
use crate::utils::auth_token::{AUTH_TOKEN_CIPHER_LEN, TokenDataPlain, UserAuthToken};
use crate::ut_registry_guard;

#[test]
fn user_auth_token_test() {
    let _guard = ut_registry_guard!();
    log_i!("user_auth_token_test start");

    let token_data_plain = TokenDataPlain {
        challenge: [0u8; CHALLENGE_LEN],
        time: 1000,
        auth_trust_level: AuthTrustLevel::Atl3,
        auth_type: AuthType::CompanionDevice,
        schedule_mode: 1,
        security_level: AuthSecurityLevel::Asl3,
        token_type: 1,
    };
    let user_auth_token = UserAuthToken::new(
        1,
        token_data_plain,
        [0u8; AUTH_TOKEN_CIPHER_LEN],
        [0u8; AES_GCM_TAG_SIZE],
        [0u8; AES_GCM_IV_SIZE],
        [0u8; SHA256_DIGEST_SIZE],
    );

    let token_silce = user_auth_token.serialize();
    let result = UserAuthToken::deserialize(token_silce);
    assert!(result.is_ok());

    let deserialize_token = result.unwrap();
    assert_eq!(user_auth_token, deserialize_token);

    let result = UserAuthToken::deserialize(&[]);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
