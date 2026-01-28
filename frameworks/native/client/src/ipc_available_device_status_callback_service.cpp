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

#include "ipc_available_device_status_callback_service.h"

#include <memory>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "common_defines.h"
#include "companion_device_auth_common_defines.h"

#define LOG_TAG "CDA_SDK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
IpcAvailableDeviceStatusCallbackService::IpcAvailableDeviceStatusCallbackService(
    const std::shared_ptr<IAvailableDeviceStatusCallback> &impl)
    : callback_(impl)
{
}

int32_t IpcAvailableDeviceStatusCallbackService::OnAvailableDeviceStatusChange(
    const std::vector<IpcDeviceStatus> &deviceStatusList)
{
    IAM_LOGI("start, deviceStatusList size:%{public}d", static_cast<int32_t>(deviceStatusList.size()));
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    ENSURE_OR_RETURN_VAL(callback_ != nullptr, GENERAL_ERROR);

    std::vector<ClientDeviceStatus> clientDeviceStatusList;
    for (const auto &deviceStatus : deviceStatusList) {
        IAM_LOGI("deviceIdType:%{public}d, deviceId:%{public}s, deviceUserId:%{public}d",
            deviceStatus.deviceKey.deviceIdType, GetMaskedString(deviceStatus.deviceKey.deviceId).c_str(),
            deviceStatus.deviceKey.deviceUserId);
        ClientDeviceKey clientDeviceKey;
        clientDeviceKey.deviceIdType = deviceStatus.deviceKey.deviceIdType;
        clientDeviceKey.deviceId = deviceStatus.deviceKey.deviceId;
        clientDeviceKey.deviceUserId = deviceStatus.deviceKey.deviceUserId;

        IAM_LOGI("deviceUserName:%{public}s, deviceModelInfo:%{public}s, deviceName:%{public}s, isOnline:%{public}d, "
                 "supportedBusinessIds size:%{public}d",
            deviceStatus.deviceUserName.c_str(), deviceStatus.deviceModelInfo.c_str(), deviceStatus.deviceName.c_str(),
            static_cast<int32_t>(deviceStatus.isOnline),
            static_cast<int32_t>(deviceStatus.supportedBusinessIds.size()));
        ClientDeviceStatus clientDeviceStatus;
        clientDeviceStatus.deviceKey = clientDeviceKey;
        clientDeviceStatus.deviceUserName = deviceStatus.deviceUserName;
        clientDeviceStatus.deviceModelInfo = deviceStatus.deviceModelInfo;
        clientDeviceStatus.deviceName = deviceStatus.deviceName;
        clientDeviceStatus.isOnline = deviceStatus.isOnline;
        clientDeviceStatus.supportedBusinessIds = deviceStatus.supportedBusinessIds;

        clientDeviceStatusList.push_back(clientDeviceStatus);
    }

    callback_->OnAvailableDeviceStatusChange(clientDeviceStatusList);
    return SUCCESS;
}

std::shared_ptr<IAvailableDeviceStatusCallback> IpcAvailableDeviceStatusCallbackService::GetCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return callback_;
}

int32_t IpcAvailableDeviceStatusCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t IpcAvailableDeviceStatusCallbackService::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS