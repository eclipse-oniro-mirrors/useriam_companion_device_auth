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

#include "common_defines.h"
#include "iam_logger.h"

#include "companion_device_auth_ffi.h"
#include "companion_device_auth_ffi_util.h"

#undef LOG_TAG
#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
int32_t CommandInvoker::Initialize()
{
    if (inited_) {
        IAM_LOGE("CommandInvoker is already inited");
        return SUCCESS;
    }
    inited_ = true;
    IAM_LOGI("initialize command invoker success");
    return SUCCESS;
}

void CommandInvoker::Uninitialize()
{
    if (!inited_) {
        IAM_LOGI("CommandInvoker is not inited");
        return;
    }
    inited_ = false;
    IAM_LOGI("uninitialize command invoker success");
}

int32_t CommandInvoker::InvokeCommand(int32_t commandId, const uint8_t *inputData, uint32_t inputDataLen,
    uint8_t *outputData, uint32_t outputDataLen)
{
    if (!inited_) {
        IAM_LOGE("CommandInvoker is not inited");
        return GENERAL_ERROR;
    }

    CommonOutputFfi commonOutputFfi = {};
    RustCommandParam param = {};
    param.commandId = commandId;
    param.callerType = 0;
    param.inputData = inputData;
    param.inputDataLen = inputDataLen;
    param.outputData = outputData;
    param.outputDataLen = outputDataLen;
    param.commonOutputData = (uint8_t *)(&commonOutputFfi);
    param.commonOutputDataLen = sizeof(commonOutputFfi);

    IAM_LOGI("command %{public}d invoke begin", commandId);
    int32_t result = invoke_rust_command(param);
    if (result != SUCCESS) {
        IAM_LOGE("command %{public}d invoke fail, result: %{public}d", commandId, result);
        return result;
    }

    CommonOutput commonOutput;
    if (!DecodeCommonOutput(commonOutputFfi, commonOutput)) {
        IAM_LOGE("command %{public}d failed to convert CommonOutputFfi", commandId);
        return GENERAL_ERROR;
    }

    if (commonOutput.result != SUCCESS) {
        IAM_LOGE("command %{public}d execute fail, result: %{public}d", commandId, commonOutput.result);
        return commonOutput.result;
    }

    IAM_LOGI("command %{public}d invoke success", commandId);
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
