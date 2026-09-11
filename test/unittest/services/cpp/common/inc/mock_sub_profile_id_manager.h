/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_TEST_MOCK_SUB_PROFILE_ID_MANAGER_H
#define COMPANION_DEVICE_AUTH_TEST_MOCK_SUB_PROFILE_ID_MANAGER_H

#include <gmock/gmock.h>

#include "sub_profile_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockSubProfileIdManager : public ISubProfileIdManager {
public:
    MOCK_METHOD(int32_t, GetForegroundSubProfileId, (UserId userId), (const, override));
    MOCK_METHOD(bool, IsForegroundSubProfileId, (UserId userId, int32_t subProfileId), (const, override));
    MOCK_METHOD(std::optional<std::string>, GetSubProfileName,
        (UserId userId, int32_t subProfileId), (const, override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeSubProfileChanged, (SubProfileChangedCallback && callback),
        (override));

    void SetupStoreSubProfileChangedCallback()
    {
        ON_CALL(*this, SubscribeSubProfileChanged(testing::_))
            .WillByDefault(testing::Invoke([this](SubProfileChangedCallback &&callback) {
                subProfileChangedCallback_ = std::move(callback);
                return std::make_unique<Subscription>([]() {});
            }));
    }

    void NotifySubProfileChanged(UserId userId, int32_t subProfileId, SubProfileEventType eventType)
    {
        if (subProfileChangedCallback_) {
            subProfileChangedCallback_(userId, subProfileId, eventType);
        }
    }

private:
    SubProfileChangedCallback subProfileChangedCallback_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_MOCK_SUB_PROFILE_ID_MANAGER_H
