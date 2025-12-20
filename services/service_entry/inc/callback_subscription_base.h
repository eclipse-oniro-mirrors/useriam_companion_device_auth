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

#include "callback_death_recipient.h"
#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

template <typename CallbackType, typename DerivedType>
class CallbackSubscriptionBase : public NoCopyable, public std::enable_shared_from_this<DerivedType> {
public:
    virtual ~CallbackSubscriptionBase() = default;

    void AddCallback(const sptr<CallbackType> &callback)
    {
        IAM_LOGI("start AddCallback");
        ENSURE_OR_RETURN(callback != nullptr);

        auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
            [&callback](const CallbackInfo &info) { return info.callback == callback; });
        if (it != callbacks_.end()) {
            IAM_LOGI("Callback already exists");
            return;
        }

        auto obj = callback->AsObject();
        ENSURE_OR_RETURN(obj != nullptr);

        sptr<IRemoteObject::DeathRecipient> deathRecipient =
            CallbackDeathRecipient::Create(obj, [weakSelf = GetWeakPtr(), callback]() {
                IAM_LOGI("callback died, remove callback");
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->RemoveCallback(callback);
            });
        ENSURE_OR_RETURN(deathRecipient != nullptr);
        callbacks_.push_back({ callback, deathRecipient });

        IAM_LOGI("end AddCallback");

        static_cast<DerivedType *>(this)->OnCallbackAdded(callback);
    }

    void RemoveCallback(const sptr<CallbackType> &callback)
    {
        IAM_LOGI("start RemoveCallback");
        ENSURE_OR_RETURN(callback != nullptr);

        auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
            [&callback](const CallbackInfo &info) { return info.callback == callback; });
        if (it != callbacks_.end()) {
            callbacks_.erase(it);
        }
        IAM_LOGI("end RemoveCallback");
    }

    bool HasCallback() const
    {
        return !callbacks_.empty();
    }

    virtual std::weak_ptr<DerivedType> GetWeakPtr() = 0;

    virtual void OnCallbackAdded(const sptr<CallbackType> &callback) = 0;

protected:
    struct CallbackInfo {
        sptr<CallbackType> callback;
        sptr<IRemoteObject::DeathRecipient> deathRecipient;
    };

    std::vector<CallbackInfo> callbacks_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CALLBACK_SUBSCRIPTION_BASE_H
