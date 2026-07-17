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

#include <algorithm>
#include <cstdint>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_DEVICE_STATUS_ENTRY

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

DeviceStatusEntry::DeviceStatusEntry(const PhysicalDeviceStatus &physicalStatus, std::function<void()> &&retrySync,
    std::vector<BusinessId> hostSupportBusinessIds)
    : physicalDeviceKey(physicalStatus.physicalDeviceKey),
      channelId(physicalStatus.channelId),
      deviceModelInfo(physicalStatus.deviceModelInfo),
      deviceUserName(),
      physicalDeviceName(physicalStatus.deviceName),
      syncDeviceName(),
      useSyncDeviceName(physicalStatus.useSyncDeviceName),
      protocolId(ProtocolId::INVALID),
      secureProtocolId(SecureProtocolId::INVALID),
      deviceType(physicalStatus.deviceType),
      capabilities(),
      isAuthMaintainActive(physicalStatus.isAuthMaintainActive),
      atlRevokeDelayMs(physicalStatus.atlRevokeDelayMs),
      refreshToken(physicalStatus.refreshToken),
      isSynced(false),
      isSyncInProgress(false),
      hostSupportBusinessIds_(std::move(hostSupportBusinessIds)),
      physicalCompanionBusinessIds_(physicalStatus.supportedBusinessIds),
      syncCompanionBusinessIds_()
{
    RecomputeEffectiveBusinessIds();

    constexpr uint32_t syncRetryBaseDelayMs = 1000;          // 1 second
    constexpr uint32_t syncRetryMaxDelayMs = 30 * 60 * 1000; // 30 minutes
    BackoffRetryTimer::Config config { .baseDelayMs = syncRetryBaseDelayMs, .maxDelayMs = syncRetryMaxDelayMs };
    syncRetryTimer_ = std::make_unique<BackoffRetryTimer>(config, std::move(retrySync));
    ENSURE_OR_RETURN(syncRetryTimer_ != nullptr);
}

DeviceStatusEntry::DeviceStatusEntry(DeviceStatusEntry &&other) noexcept
    : physicalDeviceKey(std::move(other.physicalDeviceKey)),
      channelId(other.channelId),
      deviceUserId(other.deviceUserId),
      deviceModelInfo(std::move(other.deviceModelInfo)),
      deviceUserName(std::move(other.deviceUserName)),
      physicalDeviceName(std::move(other.physicalDeviceName)),
      syncDeviceName(std::move(other.syncDeviceName)),
      useSyncDeviceName(other.useSyncDeviceName),
      protocolId(other.protocolId),
      secureProtocolId(other.secureProtocolId),
      deviceType(other.deviceType),
      capabilities(std::move(other.capabilities)),
      isAuthMaintainActive(other.isAuthMaintainActive),
      atlRevokeDelayMs(other.atlRevokeDelayMs),
      refreshToken(other.refreshToken),
      isSynced(other.isSynced),
      isSyncInProgress(other.isSyncInProgress),
      lastSyncTimeMs(other.lastSyncTimeMs),
      inProgressAttemptId(other.inProgressAttemptId),
      hostSupportBusinessIds_(std::move(other.hostSupportBusinessIds_)),
      physicalCompanionBusinessIds_(std::move(other.physicalCompanionBusinessIds_)),
      syncCompanionBusinessIds_(std::move(other.syncCompanionBusinessIds_)),
      effectiveBusinessIds_(std::move(other.effectiveBusinessIds_)),
      syncRetryTimer_(std::move(other.syncRetryTimer_))
{
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

void DeviceStatusEntry::ResetRetry()
{
    if (syncRetryTimer_ != nullptr) {
        syncRetryTimer_->ResetBackoff();
    }
}

std::string DeviceStatusEntry::GetDeviceName() const
{
    if (useSyncDeviceName && !syncDeviceName.empty()) {
        return syncDeviceName;
    }
    return physicalDeviceName;
}

DeviceKey DeviceStatusEntry::BuildDeviceKey() const
{
    DeviceKey deviceKey {};
    deviceKey.idType = physicalDeviceKey.idType;
    deviceKey.deviceId = physicalDeviceKey.deviceId;
    deviceKey.deviceUserId = deviceUserId;
    return deviceKey;
}

DeviceStatus DeviceStatusEntry::BuildDeviceStatus() const
{
    DeviceStatus status {};
    status.deviceKey.idType = physicalDeviceKey.idType;
    status.deviceKey.deviceId = physicalDeviceKey.deviceId;
    status.deviceKey.deviceUserId = deviceUserId;
    status.channelId = channelId;
    status.deviceName = GetDeviceName();
    status.deviceUserName = deviceUserName;
    status.deviceModelInfo = deviceModelInfo;
    status.protocolId = protocolId;
    status.secureProtocolId = secureProtocolId;
    status.capabilities = capabilities;
    status.supportedBusinessIds = effectiveBusinessIds_;
    status.isOnline = isSynced;
    status.isAuthMaintainActive = isAuthMaintainActive;
    status.deviceType = deviceType;
    status.atlRevokeDelayMs = atlRevokeDelayMs;
    status.refreshToken = refreshToken;
    status.lastSyncTimeMs = lastSyncTimeMs;
    return status;
}

bool DeviceStatusEntry::SetPhysicalCompanionBusinessIds(std::vector<BusinessId> physicalCompanionBusinessIds)
{
    physicalCompanionBusinessIds_ = std::move(physicalCompanionBusinessIds);
    auto previousEffective = effectiveBusinessIds_;
    RecomputeEffectiveBusinessIds();
    return previousEffective != effectiveBusinessIds_;
}

bool DeviceStatusEntry::SetSyncCompanionBusinessIds(std::vector<BusinessId> syncCompanionBusinessIds)
{
    syncCompanionBusinessIds_ = std::move(syncCompanionBusinessIds);
    auto previousEffective = effectiveBusinessIds_;
    RecomputeEffectiveBusinessIds();
    return previousEffective != effectiveBusinessIds_;
}

const std::vector<BusinessId> &DeviceStatusEntry::GetSupportedBusinessIds() const
{
    return effectiveBusinessIds_;
}

void DeviceStatusEntry::RecomputeEffectiveBusinessIds()
{
    // Sync-sourced ids are authoritative when present; otherwise degrade to the physical-layer ids.
    const std::vector<BusinessId> &deviceSupportedBusinessIds =
        syncCompanionBusinessIds_.empty() ? physicalCompanionBusinessIds_ : syncCompanionBusinessIds_;
    effectiveBusinessIds_ = IntersectBusinessIds(hostSupportBusinessIds_, deviceSupportedBusinessIds);
    IAM_LOGI("recompute effective business ids: host=%{public}s, device=%{public}s, effective=%{public}s",
        GetMaskedVectorString(hostSupportBusinessIds_).c_str(),
        GetMaskedVectorString(deviceSupportedBusinessIds).c_str(),
        GetMaskedVectorString(effectiveBusinessIds_).c_str());
}

std::vector<BusinessId> DeviceStatusEntry::IntersectBusinessIds(const std::vector<BusinessId> &hostSupportBusinessIds,
    const std::vector<BusinessId> &deviceSupportedBusinessIds)
{
    std::vector<BusinessId> effectiveBusinessIds;
    for (const auto &id : hostSupportBusinessIds) {
        if (std::find(deviceSupportedBusinessIds.begin(), deviceSupportedBusinessIds.end(), id) !=
            deviceSupportedBusinessIds.end()) {
            effectiveBusinessIds.push_back(id);
        }
    }
    return effectiveBusinessIds;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
