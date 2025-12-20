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

#ifndef COMPANION_DEVICE_AUTH_SYNC_DEVICE_STATUS_MESSAGE_H
#define COMPANION_DEVICE_AUTH_SYNC_DEVICE_STATUS_MESSAGE_H

#include <cstdint>
#include <string>
#include <vector>

#include "cda_attributes.h"
#include "common_message.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Host -> Companion
struct SyncDeviceStatusRequest {
    std::vector<ProtocolId> protocolIdList;
    std::vector<Capability> capabilityList;
    DeviceKey hostDeviceKey {};
    std::vector<uint8_t> salt;
    uint64_t challenge;
};

// Companion -> Host
struct SyncDeviceStatusReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
    std::vector<ProtocolId> protocolIdList;
    std::vector<Capability> capabilityList;
    SecureProtocolId secureProtocolId;
    DeviceKey companionDeviceKey {};
    std::string deviceUserName;
    std::vector<uint8_t> companionCheckResponse;
};

bool EncodeSyncDeviceStatusRequest(const SyncDeviceStatusRequest &request, Attributes &attributes);

bool DecodeSyncDeviceStatusRequest(const Attributes &attributes, SyncDeviceStatusRequest &request);

bool EncodeSyncDeviceStatusReply(const SyncDeviceStatusReply &reply, Attributes &attributes);

bool DecodeSyncDeviceStatusReply(const Attributes &attributes, SyncDeviceStatusReply &reply);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SYNC_DEVICE_STATUS_MESSAGE_H
