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
#include <functional>
#include <vector>

#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using AuthResultCallback = std::function<void(int32_t result, const std::vector<uint8_t> &token)>;

class IUserAuthAdapter : public NoCopyable {
public:
    virtual ~IUserAuthAdapter() = default;

    virtual uint64_t BeginDelegateAuth(uint32_t userId, const std::vector<uint8_t> &challenge, uint32_t authTrustLevel,
        AuthResultCallback callback) = 0;
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
