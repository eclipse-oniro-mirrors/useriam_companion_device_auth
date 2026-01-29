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

#ifndef COMPANION_DEVICE_AUTH_ISSUE_TOKEN_MESSAGE_H
#define COMPANION_DEVICE_AUTH_ISSUE_TOKEN_MESSAGE_H

#include <optional>

#include "cda_attributes.h"
#include "common_defines.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
// Host -> Companion
struct PreIssueTokenRequest {
    DeviceKey hostDeviceKey {};
    int32_t companionUserId { INVALID_USER_ID };
    std::vector<uint8_t> extraInfo;
};

// Companion -> Host
struct PreIssueTokenReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
    std::vector<uint8_t> extraInfo;
};

// Host -> Companion
struct IssueTokenRequest {
    DeviceKey hostDeviceKey {};
    int32_t companionUserId { INVALID_USER_ID };
    std::vector<uint8_t> extraInfo;
};

// Companion -> Host
struct IssueTokenReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
    std::vector<uint8_t> extraInfo;
};

void EncodePreIssueTokenRequest(const PreIssueTokenRequest &request, Attributes &attributes);
std::optional<PreIssueTokenRequest> DecodePreIssueTokenRequest(const Attributes &attributes);
void EncodePreIssueTokenReply(const PreIssueTokenReply &reply, Attributes &attributes);
std::optional<PreIssueTokenReply> DecodePreIssueTokenReply(const Attributes &attributes);

void EncodeIssueTokenRequest(const IssueTokenRequest &request, Attributes &attributes);
std::optional<IssueTokenRequest> DecodeIssueTokenRequest(const Attributes &attributes);
void EncodeIssueTokenReply(const IssueTokenReply &reply, Attributes &attributes);
std::optional<IssueTokenReply> DecodeIssueTokenReply(const Attributes &attributes);
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_ISSUE_TOKEN_MESSAGE_H
