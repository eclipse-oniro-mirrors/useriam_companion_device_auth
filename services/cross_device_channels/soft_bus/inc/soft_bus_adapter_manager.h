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

#ifndef SOFT_BUS_ADAPTER_MANAGER_H
#define SOFT_BUS_ADAPTER_MANAGER_H

#include <memory>

#include "device_manager_adapter.h"
#include "nocopyable.h"

#include "soft_bus_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SoftBusAdapterManager : public NoCopyable {
public:
    static SoftBusAdapterManager &GetInstance();

    bool CreateAndRegisterAdapters();

    IDeviceManagerAdapter &GetDeviceManagerAdapter();
    void SetDeviceManagerAdapter(std::shared_ptr<IDeviceManagerAdapter> adapter);

    ISoftBusAdapter &GetSoftBusAdapter();
    void SetSoftBusAdapter(std::shared_ptr<ISoftBusAdapter> adapter);

#ifdef ENABLE_TEST
    void Reset();
#endif // ENABLE_TEST

private:
    SoftBusAdapterManager() = default;
    ~SoftBusAdapterManager() = default;

    void AbortIfAdapterUninitialized(const char *adapterName);

    std::shared_ptr<IDeviceManagerAdapter> deviceManagerAdapter_;
    std::shared_ptr<ISoftBusAdapter> softBusAdapter_;
};

inline IDeviceManagerAdapter &GetDeviceManagerAdapter()
{
    return SoftBusAdapterManager::GetInstance().GetDeviceManagerAdapter();
}

inline ISoftBusAdapter &GetSoftBusAdapter()
{
    return SoftBusAdapterManager::GetInstance().GetSoftBusAdapter();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // SOFT_BUS_ADAPTER_MANAGER_H
