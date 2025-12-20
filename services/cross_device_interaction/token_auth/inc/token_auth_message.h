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

#ifndef COMPANION_DEVICE_AUTH_TOKEN_AUTH_MESSAGE_H
#define COMPANION_DEVICE_AUTH_TOKEN_AUTH_MESSAGE_H

#include <optional>

#include "cda_attributes.h"
#include "common_defines.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
// Host -> Companion
struct TokenAuthRequest {
    DeviceKey hostDeviceKey {};
    int32_t companionUserId { INVALID_USER_ID };
    std::vector<uint8_t> extraInfo;
};

// Companion -> Host
struct TokenAuthReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
    std::vector<uint8_t> extraInfo;
};

bool EncodeTokenAuthRequest(const TokenAuthRequest &request, Attributes &attributes);
std::optional<TokenAuthRequest> DecodeTokenAuthRequest(const Attributes &attributes);
bool EncodeTokenAuthReply(const TokenAuthReply &reply, Attributes &attributes);
std::optional<TokenAuthReply> DecodeTokenAuthReply(const Attributes &attributes);
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TOKEN_AUTH_MESSAGE_H
