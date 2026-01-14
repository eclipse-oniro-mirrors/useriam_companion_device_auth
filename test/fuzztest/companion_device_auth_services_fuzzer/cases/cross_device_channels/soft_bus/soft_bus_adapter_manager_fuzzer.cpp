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

#include "fuzzer/FuzzedDataProvider.h"

#include "adapter_initializer.h"
#include "channel_adapter_initializer.h"
#include "fuzz_registry.h"
#include "soft_bus_adapter_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

void FuzzSoftBusAdapterManager(FuzzedDataProvider &fuzzData)
{
    // Test GetDeviceManagerAdapter
    (void)SoftBusAdapterManager::GetInstance().GetDeviceManagerAdapter();

    // Test GetSoftBusAdapter
    (void)SoftBusAdapterManager::GetInstance().GetSoftBusAdapter();
}

FUZZ_REGISTER(SoftBusAdapterManager);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
