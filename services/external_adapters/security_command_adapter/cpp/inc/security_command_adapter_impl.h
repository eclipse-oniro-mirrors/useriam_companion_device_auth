/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_SECURITY_COMMAND_ADAPTER_IMPL_H
#define COMPANION_DEVICE_AUTH_SECURITY_COMMAND_ADAPTER_IMPL_H

#include <cstdint>

#include "security_command_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Rust ErrorCode enumeration (mirrors services/security_agent/rust/common/constants.rs)
enum class RustErrorCode : int32_t {
    SUCCESS = 0,                 // ErrorCode::Success
    FAIL = 1,                    // ErrorCode::Fail
    GENERAL_ERROR = 2,           // ErrorCode::GeneralError
    TIMEOUT = 4,                 // ErrorCode::Timeout
    BAD_PARAM = 8,               // ErrorCode::BadParam
    NOT_FOUND = 10006,           // ErrorCode::NotFound
    ID_EXISTS = 10015,           // ErrorCode::IdExists
    EXCEED_LIMIT = 10018,        // ErrorCode::ExceedLimit
    TOKEN_NOT_FOUND = 20005,     // ErrorCode::TokenNotFound
    TOKEN_VERIFY_FAILED = 20006, // ErrorCode::TokenVerifyFailed
};

// Converts a Rust ErrorCode (int32_t returned by the FFI) into the CDA ResultCode. Unknown codes fall back to
// GENERAL_ERROR. Defined out-of-line in security_command_adapter_impl.cpp.
ResultCode ConvertRustErrorCode(int32_t rustErrorCode);

class SecurityCommandAdapterImpl : public ISecurityCommandAdapter {
public:
    ~SecurityCommandAdapterImpl() override;

    static std::shared_ptr<SecurityCommandAdapterImpl> Create();

    ResultCode InvokeCommand(int32_t commandId, const uint8_t *inputData, uint32_t inputDataLen, uint8_t *outputData,
        uint32_t outputDataLen) override;

private:
    ResultCode Initialize();
    SecurityCommandAdapterImpl();

    bool initialized_ = false;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SECURITY_COMMAND_ADAPTER_IMPL_H
