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
#define LOG_FILE_ID LOG_FILE_IPC_AVAILABLE_DEVICE_STATUS_CB_SERVICE

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
IpcAvailableDeviceStatusCallbackService::IpcAvailableDeviceStatusCallbackService(int32_t userId,
    const std::shared_ptr<IAvailableDeviceStatusCallback> &impl)
    : userId_(userId),
      callback_(impl)
{
}

int32_t IpcAvailableDeviceStatusCallbackService::OnAvailableDeviceStatusChange(
    const std::vector<IpcDeviceStatus> &deviceStatusList)
{
    IAM_LOGI("start, deviceStatusList size:%{public}zu", deviceStatusList.size());
    ENSURE_OR_RETURN_VAL(callback_ != nullptr, GENERAL_ERROR);

    std::vector<ClientDeviceStatus> clientDeviceStatusList;
    for (const auto &deviceStatus : deviceStatusList) {
        IAM_LOGI("key(idType:%{public}d, id:%{public}s, userId:%{public}d), "
                 "userName:%{public}s, modelInfo:%{public}s, name:%{public}s, isOnline:%{public}d, "
                 "supportedBusinessIds:%{public}s",
            deviceStatus.deviceKey.deviceIdType, GetMaskedString(deviceStatus.deviceKey.deviceId).c_str(),
            deviceStatus.deviceKey.deviceUserId, GET_MASKED_STR_CSTR(deviceStatus.deviceUserName),
            GET_MASKED_STR_CSTR(deviceStatus.deviceModelInfo), GET_MASKED_STR_CSTR(deviceStatus.deviceName),
            deviceStatus.isOnline, GetVectorString(deviceStatus.supportedBusinessIds).c_str());
        ClientDeviceKey clientDeviceKey;
        clientDeviceKey.deviceIdType = deviceStatus.deviceKey.deviceIdType;
        clientDeviceKey.deviceId = deviceStatus.deviceKey.deviceId;
        clientDeviceKey.deviceUserId = deviceStatus.deviceKey.deviceUserId;

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

int32_t IpcAvailableDeviceStatusCallbackService::GetUserId()
{
    return userId_;
}

std::shared_ptr<IAvailableDeviceStatusCallback> IpcAvailableDeviceStatusCallbackService::GetCallback()
{
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