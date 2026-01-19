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

#include "set_device_select_result_callback.h"

#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "common_defines.h"

#define LOG_TAG "CDA_SDK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
SetDeviceSelectResultCallback::SetDeviceSelectResultCallback(const sptr<IIpcSetDeviceSelectResultCallback> &callback)
    : callback_(callback)
{
}

int32_t SetDeviceSelectResultCallback::OnSetDeviceSelectResult(const ClientDeviceSelectResult &result)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    IpcDeviceSelectResult ipcResult;
    if (result.selectionContext.has_value()) {
        IAM_LOGI("selectionContext exist");
        ipcResult.selectionContext = result.selectionContext.value();
    } else {
        IAM_LOGI("selectionContext not exist");
    }

    std::vector<IpcDeviceKey> selectedDevices;
    std::vector<ClientDeviceKey> clientDeviceKeyList = result.deviceKeys;
    for (const auto &clientKey : clientDeviceKeyList) {
        IAM_LOGI("deviceIdType:%{public}d, deviceId:%{public}s, deviceUserId:%{public}d", clientKey.deviceIdType,
            GetMaskedString(clientKey.deviceId).c_str(), clientKey.deviceUserId);
        IpcDeviceKey ipcDeviceKey;
        ipcDeviceKey.deviceIdType = clientKey.deviceIdType;
        ipcDeviceKey.deviceId = clientKey.deviceId;
        ipcDeviceKey.deviceUserId = clientKey.deviceUserId;
        selectedDevices.push_back(ipcDeviceKey);
    }
    ipcResult.deviceKeys = selectedDevices;

    callback_->OnSetDeviceSelectResult(ipcResult);
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS