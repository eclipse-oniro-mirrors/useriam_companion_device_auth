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

#include <string>
#include <vector>

#include "cross_device_common.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class DeviceStatusEntry {
public:
    explicit DeviceStatusEntry(const PhysicalDeviceStatus &physicalStatus);

    void OnUserIdChange();
    DeviceKey BuildDeviceKey(UserId userId) const;
    DeviceStatus BuildDeviceStatus(UserId userId) const;
    bool IsSameDevice(const PhysicalDeviceKey &key, ChannelId id) const;

    PhysicalDeviceKey physicalDeviceKey;
    ChannelId channelId { ChannelId::INVALID };
    std::string networkId {};
    std::string deviceModelInfo {};
    std::string deviceUserName {};
    std::string deviceName {};
    ProtocolId protocolId { ProtocolId::INVALID };
    SecureProtocolId secureProtocolId { SecureProtocolId::INVALID };
    std::vector<Capability> capabilities {};
    std::vector<int32_t> supportedBusinessIds {};
    bool isAuthMaintainActive { false };
    bool isSynced { false };
    bool isSyncInProgress { false };
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_DEVICE_STATUS_ENTRY_H
