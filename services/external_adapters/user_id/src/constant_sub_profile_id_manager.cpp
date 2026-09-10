/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "service_common.h"
#include "singleton_manager.h"
#include "sub_profile_id_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_CONSTANT_SUB_PROFILE_ID_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class ConstantSubProfileIdManager final : public ISubProfileIdManager {
public:
    ConstantSubProfileIdManager() = default;
    ~ConstantSubProfileIdManager() override = default;

    int32_t GetForegroundSubProfileId(UserId userId) const override
    {
        return INVALID_SUB_PROFILE_ID;
    }

    bool IsForegroundSubProfileId(UserId userId, int32_t subProfileId) const override
    {
        (void)userId;
        (void)subProfileId;
        return false;
    }

    std::optional<std::string> GetSubProfileName(UserId userId, int32_t subProfileId) const override
    {
        return std::nullopt;
    }

    std::unique_ptr<Subscription> SubscribeSubProfileChanged(SubProfileChangedCallback &&callback) override
    {
        (void)callback;
        return std::make_unique<Subscription>(nullptr);
    }
};

std::shared_ptr<ISubProfileIdManager> ISubProfileIdManager::Create()
{
    auto manager = std::make_shared<ConstantSubProfileIdManager>();
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    return manager;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
