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

#include "pending_obtain_token_manager.h"

#include <utility>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "service_common.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_PENDING_OBTAIN_TOKEN_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

void PendingObtainTokenManager::Defer(int32_t userId, uint32_t lockStateAuthTypeValue,
    const std::vector<uint8_t> &fwkUnlockMsg)
{
    IAM_LOGI("deferring obtain token for userId=%{public}d, lockStateAuthTypeValue=%{public}u", userId,
        lockStateAuthTypeValue);

    auto hostBindings = GetHostBindingManager().GetAllHostBindingStatus();
    if (hostBindings.empty()) {
        IAM_LOGI("no host binding found, skip obtain token  for userId=%{public}d", userId);
        return;
    }

    auto it = pendingEntries_.find(userId);
    if (it != pendingEntries_.end()) {
        IAM_LOGI("userId %{public}d already pending, updating", userId);
        it->second.lockStateAuthTypeValue = lockStateAuthTypeValue;
        it->second.fwkUnlockMsg = fwkUnlockMsg;
        return;
    }

    PendingObtainEntry entry;
    entry.lockStateAuthTypeValue = lockStateAuthTypeValue;
    entry.fwkUnlockMsg = fwkUnlockMsg;
    pendingEntries_[userId] = std::move(entry);

    EnsureSubscription();
}

void PendingObtainTokenManager::CancelByUserId(int32_t userId)
{
    auto it = pendingEntries_.find(userId);
    if (it != pendingEntries_.end()) {
        IAM_LOGI("cancel pending obtain token for userId=%{public}d", userId);
        pendingEntries_.erase(it);
    }
    EnsureSubscription();
}

void PendingObtainTokenManager::OnAuthMaintainActiveChanged(bool isActive)
{
    if (!isActive) {
        IAM_LOGI("auth maintain inactive, keep pending entries waiting");
        return;
    }

    IAM_LOGI("auth maintain became active, triggering %{public}zu pending obtain token entries",
        pendingEntries_.size());

    auto entries = std::move(pendingEntries_);
    pendingEntries_.clear();
    for (const auto &pair : entries) {
        const auto &entry = pair.second;
        int32_t subProfileId = GetUserIdManager().GetForegroundSubProfileId(pair.first);
        GetHostBindingManager().StartObtainTokenRequests(UserKey { pair.first, subProfileId },
            entry.lockStateAuthTypeValue, entry.fwkUnlockMsg);
    }

    EnsureSubscription();
}

void PendingObtainTokenManager::EnsureSubscription()
{
    if (pendingEntries_.empty()) {
        authMaintainSubscription_.reset();
        return;
    }

    if (!authMaintainSubscription_) {
        authMaintainSubscription_ =
            GetCrossDeviceCommManager().SubscribeIsAuthMaintainActive([weakSelf = weak_from_this()](bool isActive) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->OnAuthMaintainActiveChanged(isActive);
            });
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
