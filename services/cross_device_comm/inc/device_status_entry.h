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

#ifndef COMPANION_DEVICE_AUTH_DEVICE_STATUS_ENTRY_H
#define COMPANION_DEVICE_AUTH_DEVICE_STATUS_ENTRY_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "backoff_retry_timer.h"
#include "cross_device_common.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class DeviceStatusEntry : public NoCopyable {
public:
    DeviceStatusEntry(const PhysicalDeviceStatus &physicalStatus, std::function<void()> &&retrySync,
        std::vector<BusinessId> hostSupportBusinessIds = {});
    DeviceStatusEntry(DeviceStatusEntry &&other) noexcept;

    void OnSyncSuccess();
    void OnSyncFailure();
    // External sync trigger entry point: reset the backoff delay while preserving the failure
    // budget. Distinct from OnSyncSuccess (which fully resets) so callers do not piggyback on the
    // "sync succeeded" semantics.
    void ResetRetry();
    DeviceKey BuildDeviceKey() const;
    DeviceStatus BuildDeviceStatus() const;
    std::string GetDeviceName() const;
    bool SetPhysicalCompanionBusinessIds(std::vector<BusinessId> physicalCompanionBusinessIds);
    bool SetSyncCompanionBusinessIds(std::vector<BusinessId> syncCompanionBusinessIds);
    const std::vector<BusinessId> &GetSupportedBusinessIds() const;

    PhysicalDeviceKey physicalDeviceKey;
    ChannelId channelId { ChannelId::INVALID };
    int32_t deviceUserId { INVALID_USER_ID };
    std::string deviceModelInfo {};
    std::string deviceUserName {};
    std::string physicalDeviceName {};
    std::string syncDeviceName {};
    bool useSyncDeviceName { false };
    ProtocolId protocolId { ProtocolId::INVALID };
    SecureProtocolId secureProtocolId { SecureProtocolId::INVALID };
    DeviceType deviceType { DeviceType::INVALID };
    std::vector<Capability> capabilities {};
    bool isAuthMaintainActive { false };
    std::optional<uint32_t> atlRevokeDelayMs;
    bool refreshToken { false };
    bool isSynced { false };
    bool isSyncInProgress { false };
    uint64_t inProgressAttemptId { 0 };

private:
    void RecomputeEffectiveBusinessIds();
    static std::vector<BusinessId> IntersectBusinessIds(const std::vector<BusinessId> &hostSupportBusinessIds,
        const std::vector<BusinessId> &deviceSupportedBusinessIds);

    std::vector<BusinessId> hostSupportBusinessIds_;
    std::vector<BusinessId> physicalCompanionBusinessIds_;
    std::vector<BusinessId> syncCompanionBusinessIds_;
    std::vector<BusinessId> effectiveBusinessIds_;
    std::unique_ptr<BackoffRetryTimer> syncRetryTimer_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_DEVICE_STATUS_ENTRY_H
