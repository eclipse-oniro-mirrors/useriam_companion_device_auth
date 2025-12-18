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

#include "ipc_device_select_callback_service.h"

#include "common_defines.h"
#include "companion_device_auth_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "set_device_select_result_callback.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
IpcDeviceSelectCallbackService::IpcDeviceSelectCallbackService(const std::shared_ptr<IDeviceSelectCallback> &impl)
    : callback_(impl)
{
}

int32_t IpcDeviceSelectCallbackService::OnDeviceSelect(const int32_t selectPurpose,
    const sptr<IIpcSetDeviceSelectResultCallback> &callback)
{
    IAM_LOGI("start, selectPurpose:%{public}d", selectPurpose);
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    auto setDeviceSelectResultCallback = MakeShared<SetDeviceSelectResultCallback>(callback);
    callback_->OnDeviceSelect(selectPurpose, setDeviceSelectResultCallback);
    return SUCCESS;
}

int32_t IpcDeviceSelectCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t IpcDeviceSelectCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS