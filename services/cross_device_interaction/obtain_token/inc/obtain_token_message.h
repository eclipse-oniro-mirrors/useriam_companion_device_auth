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

#ifndef COMPANION_DEVICE_AUTH_OBTAIN_TOKEN_MESSAGE_H
#define COMPANION_DEVICE_AUTH_OBTAIN_TOKEN_MESSAGE_H

#include <cstdint>
#include <string>
#include <vector>

#include "cda_attributes.h"
#include "common_message.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
// Companion -> Host
struct PreObtainTokenRequest {
    UserId hostUserId { INVALID_USER_ID };
    DeviceKey companionDeviceKey;
    std::vector<uint8_t> extraInfo;
};

// Host -> Companion
struct PreObtainTokenReply {
    int32_t result;
    RequestId requestId;
    std::vector<uint8_t> extraInfo;
};

// Companion -> Host
struct ObtainTokenRequest {
    UserId hostUserId;
    RequestId requestId;
    std::vector<uint8_t> extraInfo;
    DeviceKey companionDeviceKey;
};

// Host -> Companion
struct ObtainTokenReply {
    int32_t result;
    std::vector<uint8_t> extraInfo;
};

bool EncodePreObtainTokenRequest(const PreObtainTokenRequest &request, Attributes &attributes);
bool DecodePreObtainTokenRequest(const Attributes &attributes, PreObtainTokenRequest &request);

bool EncodePreObtainTokenReply(const PreObtainTokenReply &reply, Attributes &attributes);
bool DecodePreObtainTokenReply(const Attributes &attributes, PreObtainTokenReply &reply);

bool EncodeObtainTokenRequest(const ObtainTokenRequest &request, Attributes &attributes);
bool DecodeObtainTokenRequest(const Attributes &attributes, ObtainTokenRequest &request);

bool EncodeObtainTokenReply(const ObtainTokenReply &reply, Attributes &attributes);
bool DecodeObtainTokenReply(const Attributes &attributes, ObtainTokenReply &reply);
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_OBTAIN_TOKEN_MESSAGE_H
