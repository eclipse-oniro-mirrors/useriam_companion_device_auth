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

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"

#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "user_id_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_CONSTANT_USER_ID_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr int32_t DEFAULT_USER_ID = 100;
} // namespace

class ConstantUserIdManager final : public IUserIdManager {
public:
    ConstantUserIdManager()
    {
    }
    ~ConstantUserIdManager() override = default;

    int32_t GetActiveUserId() const override
    {
        return DEFAULT_USER_ID;
    }

    std::optional<std::string> GetActiveUserName() const override
    {
        return std::nullopt;
    }

    std::string GetActiveUserTypeName() const override
    {
        return "";
    }

    std::unique_ptr<Subscription> SubscribeActiveUserId(ActiveUserIdCallback &&callback) override
    {
        ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

        TaskRunnerManager::GetInstance().PostTaskOnResident([cb = std::move(callback)]() mutable {
            if (cb) {
                cb(DEFAULT_USER_ID);
            }
        });

        return std::make_unique<Subscription>(nullptr);
    }

    UserKey GetUnlockedActiveUserkey() const override
    {
        return UserKey { DEFAULT_USER_ID, INVALID_SUB_PROFILE_ID };
    }

    std::unique_ptr<Subscription> SubscribeUnlockedActiveUserKey(UnlockedActiveUserKeyCallback &&callback) override
    {
        ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

        TaskRunnerManager::GetInstance().PostTaskOnResident([cb = std::move(callback)]() mutable {
            if (cb) {
                cb(UserKey { DEFAULT_USER_ID, INVALID_SUB_PROFILE_ID });
            }
        });

        return std::make_unique<Subscription>(nullptr);
    }

    bool IsUserIdValid(int32_t userId) override
    {
        return userId == DEFAULT_USER_ID;
    }

    std::optional<std::vector<UserKey>> GetAllValidUserKeys() const override
    {
        return std::vector<UserKey> { { DEFAULT_USER_ID, INVALID_SUB_PROFILE_ID } };
    }

    int32_t GetForegroundSubProfileId(UserId userId) const override
    {
        return INVALID_SUB_PROFILE_ID;
    }

    bool IsForegroundSubProfileId(const UserKey &userKey) const override
    {
        (void)userKey;
        return true;
    }

    std::optional<std::vector<int32_t>> GetOsAccountSubProfileIds(UserId userId) const override
    {
        (void)userId;
        return std::vector<int32_t> { INVALID_SUB_PROFILE_ID };
    }

    std::optional<std::string> GetSubProfileName(const UserKey &userKey) const override
    {
        return std::nullopt;
    }

    std::unique_ptr<Subscription> SubscribeSubProfileChanged(SubProfileChangedCallback &&callback) override
    {
        (void)callback;
        return std::make_unique<Subscription>(nullptr);
    }
};

std::shared_ptr<IUserIdManager> IUserIdManager::Create()
{
    auto manager = std::make_shared<ConstantUserIdManager>();
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    return manager;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
