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

#ifndef COMPANION_DEVICE_AUTH_ADD_COMPANION_MESSAGE_H
#define COMPANION_DEVICE_AUTH_ADD_COMPANION_MESSAGE_H

#include <optional>

#include "cda_attributes.h"
#include "common_defines.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
// Host -> Companion
struct InitKeyNegotiationRequest {
    DeviceKey hostDeviceKey {};
    std::vector<uint8_t> extraInfo;
};

// Companion -> Host
struct InitKeyNegotiationReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
    std::vector<uint8_t> extraInfo;
};

// Host -> Companion
struct BeginAddHostBindingRequest {
    int32_t companionUserId { INVALID_USER_ID };
    std::vector<uint8_t> extraInfo;
};

// Companion -> Host
struct BeginAddHostBindingReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
    std::vector<uint8_t> extraInfo;
};

// Host -> Companion
struct EndAddHostBindingRequest {
    DeviceKey hostDeviceKey {};
    int32_t companionUserId { INVALID_USER_ID };
    ResultCode result { ResultCode::GENERAL_ERROR };
};

// Companion -> Host
struct EndAddHostBindingReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
};

bool EncodeInitKeyNegotiationRequest(const InitKeyNegotiationRequest &request, Attributes &attributes);
std::optional<InitKeyNegotiationRequest> DecodeInitKeyNegotiationRequest(const Attributes &attributes);
std::optional<InitKeyNegotiationReply> DecodeInitKeyNegotiationReply(const Attributes &attributes);
bool EncodeInitKeyNegotiationReply(const InitKeyNegotiationReply &reply, Attributes &attributes);

bool EncodeBeginAddHostBindingRequest(const BeginAddHostBindingRequest &request, Attributes &attributes);
std::optional<BeginAddHostBindingRequest> DecodeBeginAddHostBindingRequest(const Attributes &attributes);
bool EncodeBeginAddHostBindingReply(const BeginAddHostBindingReply &reply, Attributes &attributes);
std::optional<BeginAddHostBindingReply> DecodeBeginAddHostBindingReply(const Attributes &attributes);

bool EncodeEndAddHostBindingRequest(const EndAddHostBindingRequest &request, Attributes &attributes);
std::optional<EndAddHostBindingRequest> DecodeEndAddHostBindingRequest(const Attributes &attributes);
bool EncodeEndAddHostBindingReply(const EndAddHostBindingReply &reply, Attributes &attributes);
std::optional<EndAddHostBindingReply> DecodeEndAddHostBindingReply(const Attributes &attributes);
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_ADD_COMPANION_MESSAGE_H
