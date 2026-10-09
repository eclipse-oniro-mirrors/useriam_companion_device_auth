/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_SOFT_BUS_QOS_H
#define COMPANION_DEVICE_AUTH_SOFT_BUS_QOS_H

#include <cstdint>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace SoftBusQos {
constexpr int32_t MIN_BW = 1024 * 1024;
constexpr int32_t MAX_LATENCY = 30 * 1000;
constexpr int32_t MIN_LATENCY = 100;
constexpr int32_t MAX_WAIT_TIMEOUT = 30 * 1000;
} // namespace SoftBusQos

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SOFT_BUS_QOS_H
