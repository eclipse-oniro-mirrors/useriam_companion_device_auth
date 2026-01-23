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

#include "iam_logger.h"

#define LOG_TAG "CDA_SA"
namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

IpcDeviceStatus ConvertToIpcDeviceStatus(const DeviceStatus &status)
{
    IpcDeviceStatus ipcStatus {};
    ipcStatus.deviceKey.deviceIdType = static_cast<int32_t>(status.deviceKey.idType);
    ipcStatus.deviceKey.deviceId = status.deviceKey.deviceId;
    ipcStatus.deviceKey.deviceUserId = status.deviceKey.deviceUserId;
    ipcStatus.deviceUserName = status.deviceUserName;
    ipcStatus.deviceModelInfo = status.deviceModelInfo;
    ipcStatus.deviceName = status.deviceName;
    ipcStatus.isOnline = status.isOnline;
    // Convert BusinessId vector to int vector for IPC
    ipcStatus.supportedBusinessIds.reserve(status.supportedBusinessIds.size());
    for (const auto &id : status.supportedBusinessIds) {
        ipcStatus.supportedBusinessIds.push_back(static_cast<int>(id));
    }
    return ipcStatus;
}

IpcTemplateStatus ConvertToIpcTemplateStatus(const CompanionStatus &companionStatus,
    const std::optional<int64_t> &manageSubscribeTime)
{
    IpcTemplateStatus ipcStatus {};
    ipcStatus.templateId = companionStatus.templateId;
    ipcStatus.isConfirmed =
        manageSubscribeTime.has_value() && (companionStatus.lastCheckTime >= manageSubscribeTime.value());
    ipcStatus.isValid = companionStatus.isValid;
    ipcStatus.localUserId = companionStatus.hostUserId;
    ipcStatus.addedTime = companionStatus.addedTime;
    // Convert BusinessId vector to int vector for IPC
    ipcStatus.enabledBusinessIds.reserve(companionStatus.enabledBusinessIds.size());
    for (const auto &id : companionStatus.enabledBusinessIds) {
        ipcStatus.enabledBusinessIds.push_back(static_cast<int>(id));
    }
    ipcStatus.deviceStatus = ConvertToIpcDeviceStatus(companionStatus.companionDeviceStatus);
    return ipcStatus;
}

bool IpcDeviceStatusEqual(const IpcDeviceStatus &lhs, const IpcDeviceStatus &rhs)
{
    return lhs.deviceKey.deviceIdType == rhs.deviceKey.deviceIdType &&
        lhs.deviceKey.deviceId == rhs.deviceKey.deviceId && lhs.deviceKey.deviceUserId == rhs.deviceKey.deviceUserId &&
        lhs.deviceUserName == rhs.deviceUserName && lhs.deviceModelInfo == rhs.deviceModelInfo &&
        lhs.deviceName == rhs.deviceName && lhs.isOnline == rhs.isOnline &&
        lhs.supportedBusinessIds == rhs.supportedBusinessIds;
}

bool IpcDeviceStatusVectorEqual(const std::vector<IpcDeviceStatus> &lhs, const std::vector<IpcDeviceStatus> &rhs)
{
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (!IpcDeviceStatusEqual(lhs[i], rhs[i])) {
            return false;
        }
    }
    return true;
}

bool IpcTemplateStatusEqual(const IpcTemplateStatus &lhs, const IpcTemplateStatus &rhs)
{
    return lhs.templateId == rhs.templateId && lhs.isConfirmed == rhs.isConfirmed && lhs.isValid == rhs.isValid &&
        lhs.localUserId == rhs.localUserId && lhs.addedTime == rhs.addedTime &&
        lhs.enabledBusinessIds == rhs.enabledBusinessIds && IpcDeviceStatusEqual(lhs.deviceStatus, rhs.deviceStatus);
}

bool IpcTemplateStatusVectorEqual(const std::vector<IpcTemplateStatus> &lhs, const std::vector<IpcTemplateStatus> &rhs)
{
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (!IpcTemplateStatusEqual(lhs[i], rhs[i])) {
            return false;
        }
    }
    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
