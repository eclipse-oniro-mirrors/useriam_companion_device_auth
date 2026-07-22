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

#ifndef COMPANION_DEVICE_AUTH_ADAPTER_INITIALIZER_H
#define COMPANION_DEVICE_AUTH_ADAPTER_INITIALIZER_H

#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

bool InitializeAdapterManager(FuzzedDataProvider &fuzzData);

void CleanupAdapterManager();

// Drives an active-user change into the last SubscribeActiveUserId callback captured by the fuzz
// UserIdManager mock (and updates GetActiveUserId() to match), exercising OnActiveUserChanged paths.
void FireFuzzActiveUserIdChange(int32_t userId);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_ADAPTER_INITIALIZER_H
