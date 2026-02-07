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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_ACTIVE_USER_ID_MANAGER_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_ACTIVE_USER_ID_MANAGER_H

#include <gmock/gmock.h>

#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockUserIdManager : public IUserIdManager {
public:
    MOCK_METHOD(bool, Initialize, (), ());
    MOCK_METHOD(int32_t, GetActiveUserId, (), (const, override));
    MOCK_METHOD(std::string, GetActiveUserName, (), (const, override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeActiveUserId, (ActiveUserIdCallback && callback), (override));
    MOCK_METHOD(bool, IsUserIdValid, (int32_t userId), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_ACTIVE_USER_ID_MANAGER_H
