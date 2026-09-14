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

#ifndef COMPANION_DEVICE_AUTH_TEST_FAKE_SUB_PROFILE_ID_MANAGER_H
#define COMPANION_DEVICE_AUTH_TEST_FAKE_SUB_PROFILE_ID_MANAGER_H

#include "sub_profile_id_manager.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Fake SubProfileIdManager for module tests.
// The production ConstantSubProfileIdManager always returns INVALID_SUB_PROFILE_ID / false,
// which causes companion-side IsForegroundSubProfileId checks to reject all requests.
// This fake treats every sub profile as foreground, so companion-side handlers proceed
// through the normal code path.
class FakeSubProfileIdManager final : public ISubProfileIdManager {
public:
    FakeSubProfileIdManager() = default;
    ~FakeSubProfileIdManager() override = default;

    int32_t GetForegroundSubProfileId(UserId userId) const override
    {
        (void)userId;
        return DEFAULT_SUB_PROFILE_ID;
    }

    bool IsForegroundSubProfileId(UserId userId, int32_t subProfileId) const override
    {
        (void)userId;
        (void)subProfileId;
        return true;
    }

    std::optional<std::string> GetSubProfileName(UserId userId, int32_t subProfileId) const override
    {
        (void)userId;
        (void)subProfileId;
        return "test-sub-profile";
    }

    std::unique_ptr<Subscription> SubscribeSubProfileChanged(SubProfileChangedCallback &&callback) override
    {
        (void)callback;
        return std::make_unique<Subscription>([]() {});
    }

private:
    static constexpr int32_t DEFAULT_SUB_PROFILE_ID = 0;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_FAKE_SUB_PROFILE_ID_MANAGER_H
