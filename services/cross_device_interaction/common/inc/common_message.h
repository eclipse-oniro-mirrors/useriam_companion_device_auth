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

#ifndef COMPANION_DEVICE_AUTH_COMMON_MESSAGE_H
#define COMPANION_DEVICE_AUTH_COMMON_MESSAGE_H

#include <optional>
#include <vector>

#include "cda_attributes.h"
#include "service_common.h"
#include "service_converter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::optional<DeviceKey> DecodeHostDeviceKey(const Attributes &attributes);
std::optional<DeviceKey> DecodeCompanionDeviceKey(const Attributes &attributes);

bool EncodeHostDeviceKey(const DeviceKey &deviceKey, Attributes &attributes);
bool EncodeCompanionDeviceKey(const DeviceKey &deviceKey, Attributes &attributes);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMMON_MESSAGE_H
