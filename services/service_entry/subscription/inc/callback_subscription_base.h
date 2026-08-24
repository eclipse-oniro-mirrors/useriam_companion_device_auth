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

#ifndef COMPANION_DEVICE_AUTH_CALLBACK_SUBSCRIPTION_BASE_H
#define COMPANION_DEVICE_AUTH_CALLBACK_SUBSCRIPTION_BASE_H

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <vector>

#include "iremote_object.h"
#include "nocopyable.h"
#include "refbase.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "callback_death_recipient.h"
#include "task_runner_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

#undef LOG_TAG
#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_CALLBACK_SUBSCRIPTION_BASE

template <typename CallbackType, typename DerivedType>
class CallbackSubscriptionBase : public std::enable_shared_from_this<DerivedType>, public NoCopyable {
public:
    using DeathHandler = std::function<void(const sptr<CallbackType> &)>;

    static bool IsCallbackSame(const sptr<CallbackType> &callback1, const sptr<CallbackType> &callback2)
    {
        if (callback1 == nullptr && callback2 == nullptr) {
            return true;
        }
        if (callback1 == nullptr || callback2 == nullptr) {
            return false;
        }
        return callback1->AsObject() == callback2->AsObject();
    }

    virtual ~CallbackSubscriptionBase() = default;

    void SetDeathHandler(DeathHandler &&handler)
    {
        deathHandler_ = std::move(handler);
    }

    bool AddCallback(const sptr<CallbackType> &callback)
    {
        IAM_LOGI("start");
        ENSURE_OR_RETURN_VAL(callback != nullptr, false);

        auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
            [&callback](const sptr<CallbackType> &item) { return IsCallbackSame(item, callback); });
        if (it != callbacks_.end()) {
            IAM_LOGI("Callback already exists");
            return true;
        }

        if (callbacks_.size() >= MAX_CALLBACKS_PER_SUBSCRIPTION) {
            IAM_LOGE("callbacks limit reached (%{public}zu)", callbacks_.size());
            return false;
        }

        auto obj = callback->AsObject();
        ENSURE_OR_RETURN_VAL(obj != nullptr, false);

        wptr<CallbackType> weakCallback(callback);
        std::unique_ptr<Subscription> deathSubscription =
            CallbackDeathRecipient::Register(obj, [weakCallback, deathHandler = deathHandler_]() {
                IAM_LOGI("callback died, schedule remove callback");
                TaskRunnerManager::GetInstance().PostTaskOnResident([weakCallback, deathHandler]() {
                    ENSURE_OR_RETURN(deathHandler != nullptr);
                    sptr<CallbackType> cb = weakCallback.promote();
                    ENSURE_OR_RETURN(cb != nullptr);
                    deathHandler(cb);
                });
            });
        ENSURE_OR_RETURN_VAL(deathSubscription != nullptr, false);
        deathSubscriptions_[obj] = std::move(deathSubscription);
        callbacks_.push_back(callback);

        OnCallbackAdded(callback);
        return true;
    }

    void RemoveCallback(const sptr<CallbackType> &callback)
    {
        IAM_LOGI("start");
        ENSURE_OR_RETURN(callback != nullptr);

        auto obj = callback->AsObject();
        if (obj != nullptr) {
            deathSubscriptions_.erase(obj);
        }

        auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
            [&callback](const sptr<CallbackType> &item) { return IsCallbackSame(item, callback); });
        if (it != callbacks_.end()) {
            IAM_LOGI("Callback removed");
            callbacks_.erase(it);
        }
    }

    bool HasCallback() const
    {
        IAM_LOGI("remain callback count: %{public}zu", callbacks_.size());
        return !callbacks_.empty();
    }

    virtual std::weak_ptr<DerivedType> GetWeakPtr() = 0;

    virtual void OnCallbackAdded(const sptr<CallbackType> &callback) = 0;

    virtual void OnCallbackRemoteDied(const sptr<CallbackType> &callback) = 0;

protected:
    static constexpr size_t MAX_CALLBACKS_PER_SUBSCRIPTION = 100;

    std::vector<sptr<CallbackType>> callbacks_;
    std::map<sptr<IRemoteObject>, std::unique_ptr<Subscription>> deathSubscriptions_;
    DeathHandler deathHandler_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#undef LOG_TAG
#undef LOG_FILE_ID
#endif // COMPANION_DEVICE_AUTH_CALLBACK_SUBSCRIPTION_BASE_H
