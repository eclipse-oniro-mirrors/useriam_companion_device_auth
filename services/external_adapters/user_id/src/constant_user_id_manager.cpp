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
#include <string>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "user_id_manager.h"

#define LOG_TAG "CDA_SA"

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

    std::string GetActiveUserName() const override
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

    bool IsUserIdValid(int32_t userId) override
    {
        return userId == DEFAULT_USER_ID;
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
