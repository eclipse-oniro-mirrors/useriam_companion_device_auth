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

#include "pending_issue_token_manager.h"

#include <utility>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_safe_arithmetic.h"

#include "adapter_manager.h"
#include "relative_timer.h"
#include "service_common.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_PENDING_ISSUE_TOKEN_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr uint32_t PENDING_ISSUE_TOKEN_TIMEOUT_MS = 10000; // 10 s
constexpr uint32_t TIMEOUT_CHECK_INTERVAL_MS = 1000;       // 1 s
} // namespace

void PendingIssueTokenManager::Defer(const FreezeCommand &freezeCommand, const std::vector<uint8_t> &extraInfo)
{
    ENSURE_OR_RETURN(!freezeCommand.templateIdList.empty());

    IAM_LOGI("deferring issue token for %{public}zu templates, userId=%{public}d, templateIds=%{public}s",
        freezeCommand.templateIdList.size(), freezeCommand.userId,
        GetMaskedVectorString(freezeCommand.templateIdList).c_str());

    auto createTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    if (!createTimeMs.has_value()) {
        IAM_LOGE("failed to get steady time");
        return;
    }

    for (const auto &templateId : freezeCommand.templateIdList) {
        if (pendingEntries_.count(templateId) > 0) {
            IAM_LOGE("templateId %{public}s already pending, overwriting", GET_MASKED_NUM_CSTR(templateId));
        }
        PendingEntry msg;
        msg.userId = freezeCommand.userId;
        msg.lockStateAuthTypeValue = freezeCommand.lockStateAuthTypeValue;
        msg.fwkMsg = extraInfo;
        msg.createTimeMs = createTimeMs.value();
        pendingEntries_[templateId] = std::move(msg);
    }

    EnsureSubscription();
}

void PendingIssueTokenManager::CancelByUserId(int32_t userId)
{
    for (auto it = pendingEntries_.begin(); it != pendingEntries_.end();) {
        if (it->second.userId == userId) {
            IAM_LOGI("cancel pending issue token for userId=%{public}d", userId);
            it = pendingEntries_.erase(it);
        } else {
            ++it;
        }
    }
    EnsureSubscription();
}

void PendingIssueTokenManager::OnCompanionStatusChange(const std::vector<CompanionStatus> &companionStatusList)
{
    for (const auto &status : companionStatusList) {
        auto it = pendingEntries_.find(status.templateId);
        if (it == pendingEntries_.end()) {
            continue;
        }
        if (!status.companionDeviceStatus.isOnline) {
            IAM_LOGI("templateId %{public}s offline, skipping issue token", GET_MASKED_NUM_CSTR(status.templateId));
            continue;
        }
        IAM_LOGI("templateId %{public}s ready, triggering issue token", GET_MASKED_NUM_CSTR(status.templateId));
        auto entry = std::move(it->second);
        pendingEntries_.erase(it);
        GetCompanionManager().StartIssueTokenRequests({ status.templateId }, entry.lockStateAuthTypeValue,
            entry.fwkMsg);
    }

    EnsureSubscription();
}

void PendingIssueTokenManager::HandleTimeoutCheck()
{
    IAM_LOGI("start");
    auto nowMs = GetTimeKeeper().GetSteadyTimeMs();
    if (!nowMs.has_value()) {
        IAM_LOGE("failed to get steady time for timeout check");
        EnsureSubscription();
        return;
    }

    for (auto it = pendingEntries_.begin(); it != pendingEntries_.end();) {
        auto elapsed = SafeSub(nowMs.value(), it->second.createTimeMs);
        if (!elapsed.has_value() || elapsed.value() >= PENDING_ISSUE_TOKEN_TIMEOUT_MS) {
            IAM_LOGI("templateId %{public}s issue token timeout", GET_MASKED_NUM_CSTR(it->first));
            it = pendingEntries_.erase(it);
        } else {
            ++it;
        }
    }

    EnsureSubscription();
}

void PendingIssueTokenManager::EnsureSubscription()
{
    if (pendingEntries_.empty()) {
        companionStatusSubscription_.reset();
        timeoutCheckTimer_.reset();
        return;
    }

    if (!companionStatusSubscription_) {
        companionStatusSubscription_ = GetCompanionManager().SubscribeCompanionDeviceStatusChange(
            [weakSelf = weak_from_this()](const std::vector<CompanionStatus> &companionStatusList) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->OnCompanionStatusChange(companionStatusList);
            });
    }

    if (!timeoutCheckTimer_) {
        auto weakSelf = weak_from_this();
        timeoutCheckTimer_ = RelativeTimer::GetInstance().RegisterPeriodic(
            [weakSelf]() {
                auto self = weakSelf.lock();
                if (!self) {
                    return;
                }
                self->HandleTimeoutCheck();
            },
            TIMEOUT_CHECK_INTERVAL_MS);
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
