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

#include "security_command_adapter_impl.h"

#include "securec.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "common_defines.h"
#include "companion_device_auth_ffi.h"
#include "companion_device_auth_ffi_util.h"

#define LOG_TAG "CDA_SA"

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
    TOKEN_NOT_FOUND = 20005,     // ErrorCode::TokenNotFound
    TOKEN_VERIFY_FAILED = 20006, // ErrorCode::TokenVerifyFailed
};

struct RustErrorCodeMapping {
    RustErrorCode rustErrorCode;
    ResultCode cppResultCode;
};

static constexpr RustErrorCodeMapping RUST_ERROR_CODE_MAPPINGS[] = {
    { RustErrorCode::SUCCESS, ResultCode::SUCCESS },
    { RustErrorCode::FAIL, ResultCode::FAIL },
    { RustErrorCode::GENERAL_ERROR, ResultCode::GENERAL_ERROR },
    { RustErrorCode::TIMEOUT, ResultCode::TIMEOUT },
    { RustErrorCode::BAD_PARAM, ResultCode::INVALID_PARAMETERS },
    { RustErrorCode::NOT_FOUND, ResultCode::NOT_ENROLLED },
    { RustErrorCode::ID_EXISTS, ResultCode::INVALID_PARAMETERS },
    { RustErrorCode::TOKEN_NOT_FOUND, ResultCode::TOKEN_NOT_FOUND },
    { RustErrorCode::TOKEN_VERIFY_FAILED, ResultCode::TOKEN_VERIFY_FAILED },
};

static constexpr size_t RUST_ERROR_CODE_MAPPING_COUNT = sizeof(RUST_ERROR_CODE_MAPPINGS) / sizeof(RustErrorCodeMapping);

static ResultCode ConvertRustErrorCode(int32_t rustErrorCode)
{
    RustErrorCode rustErrCode = static_cast<RustErrorCode>(rustErrorCode);
    for (size_t i = 0; i < RUST_ERROR_CODE_MAPPING_COUNT; ++i) {
        if (RUST_ERROR_CODE_MAPPINGS[i].rustErrorCode == rustErrCode) {
            ResultCode cppCode = RUST_ERROR_CODE_MAPPINGS[i].cppResultCode;
            IAM_LOGI("convert rust error code %{public}d to ResultCode %{public}d", static_cast<int32_t>(rustErrCode),
                static_cast<int32_t>(cppCode));
            return cppCode;
        }
    }
    IAM_LOGE("unknown rust error code %{public}d, fallback to GENERAL_ERROR", rustErrorCode);
    return ResultCode::GENERAL_ERROR;
}

SecurityCommandAdapterImpl::SecurityCommandAdapterImpl()
{
}

std::shared_ptr<SecurityCommandAdapterImpl> SecurityCommandAdapterImpl::Create()
{
    auto adapter = std::shared_ptr<SecurityCommandAdapterImpl>(new (std::nothrow) SecurityCommandAdapterImpl());
    ENSURE_OR_RETURN_VAL(adapter != nullptr, nullptr);
    ResultCode ret = adapter->Initialize();
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("Failed to initialize SecurityCommandAdapterImpl");
        return nullptr;
    }
    return adapter;
}

SecurityCommandAdapterImpl::~SecurityCommandAdapterImpl()
{
    uninit_rust_env();
}

ResultCode SecurityCommandAdapterImpl::Initialize()
{
    if (initialized_) {
        IAM_LOGE("SecurityCommandAdapter is already initialized");
        return ResultCode::SUCCESS;
    }
    int32_t ret = init_rust_env();
    if (ret != 0) {
        IAM_LOGE("init_rust_env failed, ret=%{public}d", ret);
        return ResultCode::GENERAL_ERROR;
    }

    auto ffiInput = std::make_unique<InitInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);

    auto ffiOutput = std::make_unique<InitOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    ResultCode invokeResult = InvokeCommand(CommandId::INIT, reinterpret_cast<uint8_t *>(ffiInput.get()),
        sizeof(InitInputFfi), reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(InitOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    initialized_ = true;
    IAM_LOGI("initialize security command adapter success");
    return ResultCode::SUCCESS;
}

ResultCode SecurityCommandAdapterImpl::InvokeCommand(int32_t commandId, const uint8_t *inputData, uint32_t inputDataLen,
    uint8_t *outputData, uint32_t outputDataLen)
{
    ENSURE_OR_RETURN_VAL(inputData != nullptr && inputDataLen != 0, ResultCode::GENERAL_ERROR);
    ENSURE_OR_RETURN_VAL(outputData != nullptr && outputDataLen != 0, ResultCode::GENERAL_ERROR);

    if (!initialized_ && commandId != CommandId::INIT) {
        IAM_LOGE("SecurityCommandAdapter is not initialized");
        return ResultCode::GENERAL_ERROR;
    }

    CommonOutputFfi commonOutputFfi = {};
    RustCommandParam param = {};
    param.command_id = commandId;
    param.input_data = inputData;
    param.input_data_len = inputDataLen;
    param.output_data = outputData;
    param.output_data_len = outputDataLen;
    param.common_output_data = (uint8_t *)(&commonOutputFfi);
    param.common_output_data_len = sizeof(commonOutputFfi);

    IAM_LOGI("command %{public}d invoke begin", commandId);
    int32_t result = invoke_rust_command(param);
    if (result != static_cast<int32_t>(ResultCode::SUCCESS)) {
        IAM_LOGE("command %{public}d invoke fail, result: %{public}x", commandId, result);
        return ConvertRustErrorCode(result);
    }

    CommonOutput commonOutput {};
    if (!DecodeCommonOutput(commonOutputFfi, commonOutput)) {
        IAM_LOGE("command %{public}d failed to convert CommonOutputFfi", commandId);
        return ResultCode::GENERAL_ERROR;
    }

    if (commonOutput.result != static_cast<int32_t>(ResultCode::SUCCESS)) {
        IAM_LOGE("command %{public}d execute fail, result: %{public}d", commandId, commonOutput.result);
        return ConvertRustErrorCode(commonOutput.result);
    }

    IAM_LOGI("command %{public}d invoke success", commandId);
    return ResultCode::SUCCESS;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
