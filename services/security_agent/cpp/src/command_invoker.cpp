/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "command_invoker.h"

#include "securec.h"

#include "iam_logger.h"

#include "common_defines.h"
#include "companion_device_auth_ffi.h"
#include "companion_device_auth_ffi_util.h"

#undef LOG_TAG
#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Rust ErrorCode enumeration (mirrors services/security_agent/rust/common/constants.rs)
enum class RustErrorCode : int32_t {
    SUCCESS = 0,                 // ErrorCode::Success
    FAIL = 1,                    // ErrorCode::Fail
    GENERAL_ERROR = 2,           // ErrorCode::GeneralError
    CANCELED = 3,                // ErrorCode::Canceled
    TIMEOUT = 4,                 // ErrorCode::Timeout
    TYPE_NOT_SUPPORT = 5,        // ErrorCode::TypeNotSupport
    TRUST_LEVEL_NOT_SUPPORT = 6, // ErrorCode::TrustLevelNotSupport
    BUSY = 7,                    // ErrorCode::Busy
    BAD_PARAM = 8,               // ErrorCode::BadParam
    READ_PARCEL_ERROR = 9,       // ErrorCode::ReadParcelError
    WRITE_PARCEL_ERROR = 10,     // ErrorCode::WriteParcelError
    NOT_FOUND = 11,              // ErrorCode::NotFound
    BAD_SIGN = 12,               // ErrorCode::BadSign
    ID_EXISTS = 13,              // ErrorCode::IdExists
    EXCEED_LIMIT = 14,           // ErrorCode::ExceedLimit
};

struct RustErrorCodeMapping {
    RustErrorCode rustErrorCode;
    ResultCode cppResultCode;
};

static constexpr RustErrorCodeMapping RUST_ERROR_CODE_MAPPINGS[] = {
    { RustErrorCode::SUCCESS, ResultCode::SUCCESS },
    { RustErrorCode::FAIL, ResultCode::FAIL },
    { RustErrorCode::GENERAL_ERROR, ResultCode::GENERAL_ERROR },
    { RustErrorCode::CANCELED, ResultCode::CANCELED },
    { RustErrorCode::TIMEOUT, ResultCode::TIMEOUT },
    { RustErrorCode::TYPE_NOT_SUPPORT, ResultCode::TYPE_NOT_SUPPORT },
    { RustErrorCode::TRUST_LEVEL_NOT_SUPPORT, ResultCode::TRUST_LEVEL_NOT_SUPPORT },
    { RustErrorCode::BUSY, ResultCode::BUSY },
    { RustErrorCode::BAD_PARAM, ResultCode::INVALID_PARAMETERS },
    { RustErrorCode::READ_PARCEL_ERROR, ResultCode::GENERAL_ERROR },
    { RustErrorCode::WRITE_PARCEL_ERROR, ResultCode::GENERAL_ERROR },
    { RustErrorCode::NOT_FOUND, ResultCode::NOT_ENROLLED },
    { RustErrorCode::BAD_SIGN, ResultCode::AUTH_TOKEN_CHECK_FAILED },
    { RustErrorCode::ID_EXISTS, ResultCode::INVALID_PARAMETERS },
    { RustErrorCode::EXCEED_LIMIT, ResultCode::LOCKED },
};

static constexpr size_t RUST_ERROR_CODE_MAPPING_COUNT = sizeof(RUST_ERROR_CODE_MAPPINGS) / sizeof(RustErrorCodeMapping);

ResultCode ConvertRustErrorCode(int32_t rustErrorCode)
{
    RustErrorCode rustErrCode = static_cast<RustErrorCode>(rustErrorCode);
    for (size_t i = 0; i < RUST_ERROR_CODE_MAPPING_COUNT; ++i) {
        if (RUST_ERROR_CODE_MAPPINGS[i].rustErrorCode == rustErrCode) {
            return RUST_ERROR_CODE_MAPPINGS[i].cppResultCode;
        }
    }
    return ResultCode::GENERAL_ERROR;
}

std::shared_ptr<ICommandInvoker> ICommandInvoker::Create()
{
    return std::make_shared<CommandInvoker>();
}

CommandInvoker::CommandInvoker()
{
    init_rust_env();
}

CommandInvoker::~CommandInvoker()
{
    uninit_rust_env();
}

ResultCode CommandInvoker::Initialize()
{
    if (inited_) {
        IAM_LOGE("CommandInvoker is already inited");
        return ResultCode::SUCCESS;
    }
    inited_ = true;
    IAM_LOGI("initialize command invoker success");
    return ResultCode::SUCCESS;
}

void CommandInvoker::Finalize()
{
    if (!inited_) {
        IAM_LOGI("CommandInvoker is not inited");
        return;
    }
    inited_ = false;
    IAM_LOGI("uninitialize command invoker success");
}

ResultCode CommandInvoker::InvokeCommand(int32_t commandId, const uint8_t *inputData, uint32_t inputDataLen,
    uint8_t *outputData, uint32_t outputDataLen)
{
    if (!inited_) {
        IAM_LOGE("CommandInvoker is not inited");
        return ResultCode::GENERAL_ERROR;
    }

    CommonOutputFfi commonOutputFfi = {};
    RustCommandParam param = {};
    param.commandId = commandId;
    param.inputData = inputData;
    param.inputDataLen = inputDataLen;
    param.outputData = outputData;
    param.outputDataLen = outputDataLen;
    param.commonOutputData = (uint8_t *)(&commonOutputFfi);
    param.commonOutputDataLen = sizeof(commonOutputFfi);

    IAM_LOGI("command %{public}d invoke begin", commandId);
    int32_t result = invoke_rust_command(param);
    if (result != static_cast<int32_t>(ResultCode::SUCCESS)) {
        IAM_LOGE("command %{public}d invoke fail, result: %{public}x", commandId, result);
        return ConvertRustErrorCode(result);
    }

    CommonOutput commonOutput;
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
