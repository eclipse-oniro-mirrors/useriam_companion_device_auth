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

#ifndef COMPANION_DEVICE_AUTH_USER_AUTH_ADAPTER_H
#define COMPANION_DEVICE_AUTH_USER_AUTH_ADAPTER_H

#include <cstdint>
#include <memory>
#include <vector>

#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthenticationCallback;
struct WidgetAuthParam;
struct WidgetParam;
} // namespace UserAuth
} // namespace UserIam

namespace UserIam {
namespace CompanionDeviceAuth {

class IUserAuthAdapter : public NoCopyable {
public:
    virtual ~IUserAuthAdapter() = default;

    // Simplified version for basic delegate auth with default settings
    virtual uint64_t BeginDelegateAuth(uint32_t userId, const std::vector<uint8_t> &challenge, uint32_t authTrustLevel,
        const std::shared_ptr<UserAuth::AuthenticationCallback> &callback) = 0;

    // Full version with complete WidgetAuthParam and WidgetParam configuration
    virtual uint64_t BeginWidgetAuth(const UserAuth::WidgetAuthParam &authParam,
        const UserAuth::WidgetParam &widgetParam,
        const std::shared_ptr<UserAuth::AuthenticationCallback> &callback) = 0;

    virtual int32_t CancelAuthentication(uint64_t contextId) = 0;

#ifndef ENABLE_TEST
protected:
#endif
    IUserAuthAdapter() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_USER_AUTH_ADAPTER_H
