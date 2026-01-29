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

#ifndef COMPANION_DEVICE_AUTH_DELEGATE_AUTH_MESSAGE_H
#define COMPANION_DEVICE_AUTH_DELEGATE_AUTH_MESSAGE_H

#include <optional>

#include "cda_attributes.h"
#include "common_defines.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
// Host -> Companion
struct StartDelegateAuthRequest {
    DeviceKey hostDeviceKey {};
    int32_t companionUserId { INVALID_USER_ID };
    std::vector<uint8_t> extraInfo;
};

// Companion -> Host
struct StartDelegateAuthReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
};

// Companion -> Host
struct SendDelegateAuthResultRequest {
    ResultCode result { ResultCode::GENERAL_ERROR };
    std::vector<uint8_t> extraInfo;
};

// Host -> Companion
struct SendDelegateAuthResultReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
};

void EncodeStartDelegateAuthRequest(const StartDelegateAuthRequest &request, Attributes &attributes);
std::optional<StartDelegateAuthRequest> DecodeStartDelegateAuthRequest(const Attributes &attributes);
void EncodeStartDelegateAuthReply(const StartDelegateAuthReply &reply, Attributes &attributes);
std::optional<StartDelegateAuthReply> DecodeStartDelegateAuthReply(const Attributes &attributes);

void EncodeSendDelegateAuthResultRequest(const SendDelegateAuthResultRequest &request, Attributes &attributes);
std::optional<SendDelegateAuthResultRequest> DecodeSendDelegateAuthResultRequest(const Attributes &attributes);
void EncodeSendDelegateAuthResultReply(const SendDelegateAuthResultReply &reply, Attributes &attributes);
std::optional<SendDelegateAuthResultReply> DecodeSendDelegateAuthResultReply(const Attributes &attributes);
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_DELEGATE_AUTH_MESSAGE_H
