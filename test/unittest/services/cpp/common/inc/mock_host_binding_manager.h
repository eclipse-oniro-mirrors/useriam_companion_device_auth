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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_HOST_BINDING_MANAGER_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_HOST_BINDING_MANAGER_H

#include <gmock/gmock.h>

#include "host_binding_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockHostBindingManager : public IHostBindingManager {
public:
    MOCK_METHOD(std::optional<HostBindingStatus>, GetHostBindingStatus, (BindingId bindingId), (override));
    MOCK_METHOD(std::optional<HostBindingStatus>, GetHostBindingStatus,
        (const UserKey &companionUserKey, const DeviceKey &hostDeviceKey), (override));
    MOCK_METHOD(ResultCode, BeginAddHostBinding,
        (const BeginAddHostBindingInput &input, BeginAddHostBindingOutput &output), (override));
    MOCK_METHOD(ResultCode, EndAddHostBinding, (const EndAddHostBindingInput &input, EndAddHostBindingOutput &output),
        (override));
    MOCK_METHOD(ResultCode, RemoveHostBinding,
        (const UserKey &companionUserKey, const DeviceKey &hostDeviceKey), (override));
    MOCK_METHOD(bool, SetHostBindingTokenValid, (BindingId bindingId, bool isTokenValid), (override));
    MOCK_METHOD(void, StartObtainTokenRequests,
        (const UserKey &activeUserKey, uint32_t lockStateAuthTypeValue, const std::vector<uint8_t> &fwkUnlockMsg),
        (override));
    MOCK_METHOD(void, RevokeTokens, (UserId userId, const std::string &reason), (override));
    MOCK_METHOD(std::vector<HostBindingStatus>, GetAllHostBindingStatus, (), (override));

private:
    MOCK_METHOD(bool, Initialize, (), ());
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_HOST_BINDING_MANAGER_H
