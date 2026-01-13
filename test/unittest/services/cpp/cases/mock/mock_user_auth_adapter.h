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

#ifndef MOCK_USER_AUTH_ADAPTER_H
#define MOCK_USER_AUTH_ADAPTER_H

#include <cstdint>
#include <functional>
#include <vector>

#include <gmock/gmock.h>

#include "user_auth_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockUserAuthAdapter : public IUserAuthAdapter {
public:
    MOCK_METHOD(uint64_t, BeginDelegateAuth,
        (uint32_t userId, const std::vector<uint8_t> &challenge, uint32_t authTrustLevel, AuthResultCallback callback),
        (override));
    MOCK_METHOD(int32_t, CancelAuthentication, (uint64_t contextId), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_USER_AUTH_ADAPTER_H
