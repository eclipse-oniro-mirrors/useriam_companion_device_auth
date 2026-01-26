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

#include <cstdint>

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SA"
namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

DeviceStatusEntry::DeviceStatusEntry(const PhysicalDeviceStatus &physicalStatus, std::function<void()> &&retrySync)
    : physicalDeviceKey(physicalStatus.physicalDeviceKey),
      channelId(physicalStatus.channelId),
      deviceModelInfo(physicalStatus.deviceModelInfo),
      deviceName(physicalStatus.deviceName),
      isAuthMaintainActive(physicalStatus.isAuthMaintainActive),
      isSynced(false),
      isSyncInProgress(false)
{
    constexpr uint32_t syncRetryBaseDelayMs = 1000;          // 1 second
    constexpr uint32_t syncRetryMaxDelayMs = 30 * 60 * 1000; // 30 minutes
    BackoffRetryTimer::Config config { .baseDelayMs = syncRetryBaseDelayMs, .maxDelayMs = syncRetryMaxDelayMs };
    syncRetryTimer_ = std::make_unique<BackoffRetryTimer>(config, std::move(retrySync));
    ENSURE_OR_RETURN(syncRetryTimer_ != nullptr);
}

DeviceStatusEntry::DeviceStatusEntry(DeviceStatusEntry &&other) noexcept
    : physicalDeviceKey(std::move(other.physicalDeviceKey)),
      channelId(other.channelId),
      deviceModelInfo(std::move(other.deviceModelInfo)),
      deviceUserName(std::move(other.deviceUserName)),
      deviceName(std::move(other.deviceName)),
      protocolId(other.protocolId),
      secureProtocolId(other.secureProtocolId),
      capabilities(std::move(other.capabilities)),
      supportedBusinessIds(std::move(other.supportedBusinessIds)),
      isAuthMaintainActive(other.isAuthMaintainActive),
      isSynced(other.isSynced),
      isSyncInProgress(other.isSyncInProgress),
      syncRetryTimer_(std::move(other.syncRetryTimer_))
{
}

void DeviceStatusEntry::OnUserIdChange()
{
    isSynced = false;
    isSyncInProgress = false;
    deviceName.clear();
    if (syncRetryTimer_ != nullptr) {
        syncRetryTimer_->Reset();
    }
}

void DeviceStatusEntry::OnSyncSuccess()
{
    if (syncRetryTimer_ != nullptr) {
        syncRetryTimer_->Reset();
    }
}

void DeviceStatusEntry::OnSyncFailure()
{
    if (syncRetryTimer_ != nullptr) {
        syncRetryTimer_->OnFailure();
    }
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
