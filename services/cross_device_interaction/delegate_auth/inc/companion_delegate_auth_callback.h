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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_DELEGATE_AUTH_CALLBACK_H
#define COMPANION_DEVICE_AUTH_COMPANION_DELEGATE_AUTH_CALLBACK_H

#include <functional>
#include <optional>
#include <vector>

#include "user_auth_client_callback.h"

#include "service_common.h"
#include "task_runner_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionDelegateAuthCallback : public UserAuth::AuthenticationCallback,
                                      public std::enable_shared_from_this<CompanionDelegateAuthCallback> {
public:
    using ResultCallback = std::function<void(ResultCode result, const std::vector<uint8_t> &extraInfo)>;
    CompanionDelegateAuthCallback(ResultCallback &&callback);
    virtual ~CompanionDelegateAuthCallback() = default;

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const UserAuth::Attributes &extraInfo) override;
    void OnResult(int32_t result, const UserAuth::Attributes &extraInfo) override;

#ifndef ENABLE_TEST
private:
#endif
    void HandleResult(int32_t result, const std::vector<uint8_t> &data);

    ResultCallback callback_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_DELEGATE_AUTH_CALLBACK_H
