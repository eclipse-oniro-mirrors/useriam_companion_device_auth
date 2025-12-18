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

#include "callback_death_recipient.h"

#include <functional>
#include <memory>

#include "iam_check.h"
#include "iam_logger.h"
#include "service_common.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

sptr<CallbackDeathRecipient> CallbackDeathRecipient::Create(const sptr<IRemoteObject> &remoteObj,
    DeathCallback &&callback)
{
    ENSURE_OR_RETURN_VAL(remoteObj != nullptr, nullptr);
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    sptr<CallbackDeathRecipient> recipient(new (std::nothrow) CallbackDeathRecipient(remoteObj, std::move(callback)));
    if (recipient == nullptr) {
        IAM_LOGE("failed to create CallbackDeathRecipient");
        return nullptr;
    }

    if (!recipient->Init()) {
        IAM_LOGE("failed to init CallbackDeathRecipient");
        return nullptr;
    }

    return recipient;
}

CallbackDeathRecipient::CallbackDeathRecipient(const sptr<IRemoteObject> &remoteObj, DeathCallback &&callback)
    : callback_(std::move(callback)),
      remoteObj_(remoteObj)
{
}

CallbackDeathRecipient::~CallbackDeathRecipient()
{
    if (!initialized_) {
        return;
    }

    auto obj = remoteObj_.promote();
    if (obj != nullptr) {
        obj->RemoveDeathRecipient(this);
    }
}

bool CallbackDeathRecipient::Init()
{
    auto obj = remoteObj_.promote();
    ENSURE_OR_RETURN_VAL(obj != nullptr, false);

    if (initialized_) {
        IAM_LOGW("already initialized");
        return false;
    }

    if (!obj->AddDeathRecipient(this)) {
        IAM_LOGE("AddDeathRecipient failed");
        return false;
    }

    initialized_ = true;
    return true;
}

void CallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    (void)remote;
    IAM_LOGI("remote object died, executing cleanup callback");

    DeathCallback callback = callback_;

    if (!callback) {
        return;
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident([cb = std::move(callback)]() mutable {
        if (cb) {
            cb();
        }
    });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
