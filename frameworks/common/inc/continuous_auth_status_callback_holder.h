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

#ifndef CONTINUOUS_AUTH_STATUS_CALLBACK_HOLDER_H
#define CONTINUOUS_AUTH_STATUS_CALLBACK_HOLDER_H

#include "callback_holder.h"
#include "continuous_auth_status_callback_wrapper.h"
#include "icontinuous_auth_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
template <typename T>
class ContinuousAuthStatusCallbackHolder : public IContinuousAuthStatusCallback,
                                           public CallbackHolder<ContinuousAuthStatusCallbackWrapper<T>> {
public:
    ContinuousAuthStatusCallbackHolder() = default;
    ~ContinuousAuthStatusCallbackHolder() = default;

    void OnCallbackAdded(const std::shared_ptr<ContinuousAuthStatusCallbackWrapper<T>> &callback) override
    {
        std::lock_guard<std::recursive_mutex> lock(this->mutex_);
        if (callback != nullptr && hasCached_) {
            callback->OnContinuousAuthStatusChange(cachedIsAuthPassed_, cachedAuthTrustLevel_);
        }
    }

    void OnContinuousAuthStatusChange(const bool isAuthPassed, const std::optional<int32_t> authTrustLevel) override
    {
        std::vector<std::shared_ptr<ContinuousAuthStatusCallbackWrapper<T>>> callbacks;
        {
            std::lock_guard<std::recursive_mutex> lock(this->mutex_);
            cachedIsAuthPassed_ = isAuthPassed;
            cachedAuthTrustLevel_ = authTrustLevel;
            hasCached_ = true;
            callbacks = this->GetCallbacksUnchecked();
        }
        for (const auto &callback : callbacks) {
            if (callback != nullptr) {
                callback->OnContinuousAuthStatusChange(isAuthPassed, authTrustLevel);
            }
        }
    }

private:
    bool cachedIsAuthPassed_ = false;
    std::optional<int32_t> cachedAuthTrustLevel_;
    bool hasCached_ = false;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // CONTINUOUS_AUTH_STATUS_CALLBACK_HOLDER_H