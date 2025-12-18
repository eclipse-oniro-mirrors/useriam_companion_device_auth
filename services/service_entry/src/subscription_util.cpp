/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "subscription_util.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

IpcDeviceStatus ConvertToIpcDeviceStatus(const DeviceStatus &status)
{
    IpcDeviceStatus ipcStatus;
    ipcStatus.deviceKey.deviceIdType = static_cast<int32_t>(status.deviceKey.idType);
    ipcStatus.deviceKey.deviceId = status.deviceKey.deviceId;
    ipcStatus.deviceKey.deviceUserId = status.deviceKey.deviceUserId;
    ipcStatus.deviceUserName = status.deviceUserName;
    ipcStatus.deviceModelInfo = status.deviceModelInfo;
    ipcStatus.deviceName = status.deviceName;
    ipcStatus.isOnline = status.isOnline;
    ipcStatus.supportedBusinessIds = status.supportedBusinessIds;
    return ipcStatus;
}

IpcTemplateStatus ConvertToIpcTemplateStatus(const CompanionStatus &companionStatus,
    const std::optional<int64_t> &manageSubscribeTime)
{
    IpcTemplateStatus ipcStatus;
    ipcStatus.templateId = companionStatus.templateId;
    ipcStatus.isConfirmed =
        manageSubscribeTime.has_value() && (companionStatus.lastCheckTime >= manageSubscribeTime.value());
    ipcStatus.isValid = companionStatus.isValid;
    ipcStatus.localUserId = companionStatus.hostUserId;
    ipcStatus.addedTime = companionStatus.addedTime;
    ipcStatus.enabledBusinessIds = companionStatus.enabledBusinessIds;
    ipcStatus.deviceStatus = ConvertToIpcDeviceStatus(companionStatus.companionDeviceStatus);
    return ipcStatus;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
