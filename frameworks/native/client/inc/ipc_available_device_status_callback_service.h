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

#ifndef IPC_AVAILABLE_DEVICE_STATUS_CALLBACK_SERVICE_H
#define IPC_AVAILABLE_DEVICE_STATUS_CALLBACK_SERVICE_H

#include <mutex>
#include <vector>

#include "companion_device_auth_types.h"
#include "iavailable_device_status_callback.h"
#include "ipc_available_device_status_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class IpcAvailableDeviceStatusCallbackService : public IpcAvailableDeviceStatusCallbackStub {
public:
    explicit IpcAvailableDeviceStatusCallbackService(int32_t userId,
        const std::shared_ptr<IAvailableDeviceStatusCallback> &impl);
    ~IpcAvailableDeviceStatusCallbackService() override = default;

    int32_t OnAvailableDeviceStatusChange(const std::vector<IpcDeviceStatus> &deviceStatusList) override;

    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

    int32_t GetUserId();
    std::shared_ptr<IAvailableDeviceStatusCallback> GetCallback();

private:
    int32_t userId_ { -1 };
    std::shared_ptr<IAvailableDeviceStatusCallback> callback_ { nullptr };
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // IPC_AVAILABLE_DEVICE_STATUS_CALLBACK_SERVICE_H