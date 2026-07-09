/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_RESYNC_DEVICE_STATUS_MESSAGE_H
#define COMPANION_DEVICE_AUTH_RESYNC_DEVICE_STATUS_MESSAGE_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "cda_attributes.h"
#include "common_message.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Companion -> Host:
struct RequestDeviceResyncRequest {
    DeviceKey companionDeviceKey {};
};

// Host -> Companion
struct RequestDeviceResyncReply {
    ResultCode result { ResultCode::SUCCESS };
};

void EncodeRequestDeviceResyncRequest(const RequestDeviceResyncRequest &request, Attributes &attributes);

std::optional<RequestDeviceResyncRequest> DecodeRequestDeviceResyncRequest(const Attributes &attributes);

void EncodeRequestDeviceResyncReply(const RequestDeviceResyncReply &reply, Attributes &attributes);

std::optional<RequestDeviceResyncReply> DecodeRequestDeviceResyncReply(const Attributes &attributes);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_RESYNC_DEVICE_STATUS_MESSAGE_H
