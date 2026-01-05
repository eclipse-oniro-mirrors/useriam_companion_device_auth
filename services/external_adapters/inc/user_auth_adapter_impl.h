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

#ifndef COMPANION_DEVICE_AUTH_USER_AUTH_ADAPTER_IMPL_H
#define COMPANION_DEVICE_AUTH_USER_AUTH_ADAPTER_IMPL_H

#include "user_auth_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class UserAuthAdapterImpl : public IUserAuthAdapter {
public:
    UserAuthAdapterImpl() = default;
    ~UserAuthAdapterImpl() override = default;

    uint64_t BeginDelegateAuth(uint32_t userId, const std::vector<uint8_t> &challenge, uint32_t authTrustLevel,
        const std::shared_ptr<UserAuth::AuthenticationCallback> &callback) override;
    uint64_t BeginWidgetAuth(const UserAuth::WidgetAuthParam &authParam, const UserAuth::WidgetParam &widgetParam,
        const std::shared_ptr<UserAuth::AuthenticationCallback> &callback) override;
    int32_t CancelAuthentication(uint64_t contextId) override;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_USER_AUTH_ADAPTER_IMPL_H
