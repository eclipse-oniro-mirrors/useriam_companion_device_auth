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

#ifndef IPC_CONTINUOUS_AUTH_STATUS_CALLBACK_SERVICE_H
#define IPC_CONTINUOUS_AUTH_STATUS_CALLBACK_SERVICE_H

#include <mutex>

#include "companion_device_auth_types.h"
#include "icontinuous_auth_status_callback.h"
#include "ipc_continuous_auth_status_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class IpcContinuousAuthStatusCallbackService : public IpcContinuousAuthStatusCallbackStub {
public:
    explicit IpcContinuousAuthStatusCallbackService(int32_t userId, std::optional<uint64_t> templateId,
        const std::shared_ptr<IContinuousAuthStatusCallback> &impl);
    ~IpcContinuousAuthStatusCallbackService() override = default;

    int32_t OnContinuousAuthStatusChange(const IpcContinuousAuthStatus &status) override;

    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

    int32_t GetUserId();
    std::optional<uint64_t> GetTemplateId();
    std::shared_ptr<IContinuousAuthStatusCallback> GetCallback();

private:
    int32_t userId_ { -1 };
    std::optional<uint64_t> templateId_ { std::nullopt };
    std::shared_ptr<IContinuousAuthStatusCallback> callback_ { nullptr };
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // IPC_CONTINUOUS_AUTH_STATUS_CALLBACK_SERVICE_H