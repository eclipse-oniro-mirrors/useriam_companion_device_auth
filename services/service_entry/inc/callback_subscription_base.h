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
#include <memory>
#include <vector>

#include "iremote_object.h"
#include "nocopyable.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "callback_death_recipient.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

template <typename CallbackType, typename DerivedType>
class CallbackSubscriptionBase : public NoCopyable, public std::enable_shared_from_this<DerivedType> {
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

    void SetDeathHandler(const DeathHandler &handler)
    {
        deathHandler_ = handler;
    }

    void AddCallback(const sptr<CallbackType> &callback)
    {
        IAM_LOGI("start");
        ENSURE_OR_RETURN(callback != nullptr);

        auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
            [&callback](const sptr<CallbackType> &item) { return IsCallbackSame(item, callback); });
        if (it != callbacks_.end()) {
            IAM_LOGI("Callback already exists");
            return;
        }

        auto obj = callback->AsObject();
        ENSURE_OR_RETURN(obj != nullptr);

        sptr<IRemoteObject::DeathRecipient> deathRecipient =
            CallbackDeathRecipient::Register(obj, [callback, deathHandler = deathHandler_]() {
                IAM_LOGI("callback died, schedule remove callback");
                TaskRunnerManager::GetInstance().PostTaskOnResident([callback, deathHandler]() {
                    ENSURE_OR_RETURN(deathHandler != nullptr);
                    deathHandler(callback);
                });
            });
        ENSURE_OR_RETURN(deathRecipient != nullptr);
        callbacks_.push_back(callback);

        static_cast<DerivedType *>(this)->OnCallbackAdded(callback);
    }

    void RemoveCallback(const sptr<CallbackType> &callback)
    {
        IAM_LOGI("start");
        ENSURE_OR_RETURN(callback != nullptr);

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

#ifndef ENABLE_TEST
protected:
#endif
    std::vector<sptr<CallbackType>> callbacks_;
    DeathHandler deathHandler_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CALLBACK_SUBSCRIPTION_BASE_H
