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

#include "device_status_entry.h"

#include "iam_logger.h"

#define LOG_TAG "CDA_SA"
namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

DeviceStatusEntry::DeviceStatusEntry(const PhysicalDeviceStatus &physicalStatus)
    : physicalDeviceKey(physicalStatus.physicalDeviceKey),
      channelId(physicalStatus.channelId),
      deviceModelInfo(physicalStatus.deviceModelInfo),
      deviceName(physicalStatus.deviceName),
      isAuthMaintainActive(physicalStatus.isAuthMaintainActive),
      isSynced(false),
      isSyncInProgress(false)
{
}

void DeviceStatusEntry::OnUserIdChange()
{
    isSynced = false;
    isSyncInProgress = false;
    deviceName.clear();
}

DeviceKey DeviceStatusEntry::BuildDeviceKey(UserId userId) const
{
    DeviceKey deviceKey {};
    deviceKey.idType = physicalDeviceKey.idType;
    deviceKey.deviceId = physicalDeviceKey.deviceId;
    deviceKey.deviceUserId = userId;
    return deviceKey;
}

DeviceStatus DeviceStatusEntry::BuildDeviceStatus(UserId userId) const
{
    DeviceStatus status {};
    status.deviceKey.idType = physicalDeviceKey.idType;
    status.deviceKey.deviceId = physicalDeviceKey.deviceId;
    status.deviceKey.deviceUserId = userId;
    status.channelId = channelId;
    status.deviceName = deviceName;
    status.deviceModelInfo = deviceModelInfo;
    status.protocolId = protocolId;
    status.secureProtocolId = secureProtocolId;
    status.capabilities = capabilities;
    status.supportedBusinessIds = supportedBusinessIds;
    status.isOnline = isSynced;
    status.isAuthMaintainActive = isAuthMaintainActive;
    return status;
}

bool DeviceStatusEntry::IsSameDevice(const PhysicalDeviceKey &key, ChannelId id) const
{
    return physicalDeviceKey == key && channelId == id;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
