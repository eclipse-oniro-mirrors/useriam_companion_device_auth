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

#include "time_keeper_impl.h"

#include <ctime>
#include <optional>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_safe_arithmetic.h"
#include "service_common.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<TimeKeeperImpl> TimeKeeperImpl::Create()
{
    auto keeper = std::shared_ptr<TimeKeeperImpl>(new (std::nothrow) TimeKeeperImpl());
    ENSURE_OR_RETURN_VAL(keeper != nullptr, nullptr);
    return keeper;
}

std::optional<SystemTimeMs> TimeKeeperImpl::GetSystemTimeMs()
{
    struct timespec ts {};
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        IAM_LOGE("Failed to get CLOCK_REALTIME");
        return std::nullopt;
    }

    auto secMs = safe_mul(static_cast<uint64_t>(ts.tv_sec), static_cast<uint64_t>(MS_PER_SEC));
    if (!secMs.has_value()) {
        IAM_LOGE("System time overflow: tv_sec=%{public}lld", static_cast<long long>(ts.tv_sec));
        return std::nullopt;
    }

    uint64_t ms = static_cast<uint64_t>(ts.tv_nsec) / static_cast<uint64_t>(NS_PER_MS);
    auto totalMs = safe_add(secMs.value(), ms);
    if (!totalMs.has_value()) {
        IAM_LOGE("System time overflow when adding nanoseconds");
        return std::nullopt;
    }

    return totalMs.value();
}

std::optional<SteadyTimeMs> TimeKeeperImpl::GetSteadyTimeMs()
{
    struct timespec ts {};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        IAM_LOGE("Failed to get CLOCK_MONOTONIC");
        return std::nullopt;
    }

    auto secMs = safe_mul(static_cast<uint64_t>(ts.tv_sec), static_cast<uint64_t>(MS_PER_SEC));
    if (!secMs.has_value()) {
        IAM_LOGE("Steady time overflow: tv_sec=%{public}lld", static_cast<long long>(ts.tv_sec));
        return std::nullopt;
    }

    uint64_t ms = static_cast<uint64_t>(ts.tv_nsec) / static_cast<uint64_t>(NS_PER_MS);
    auto totalMs = safe_add(secMs.value(), ms);
    if (!totalMs.has_value()) {
        IAM_LOGE("Steady time overflow when adding nanoseconds");
        return std::nullopt;
    }

    return totalMs.value();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
