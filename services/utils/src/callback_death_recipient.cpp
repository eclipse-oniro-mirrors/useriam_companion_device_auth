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

#include <memory>

#include "iam_check.h"
#include "iam_logger.h"

#include "service_common.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_CALLBACK_DEATH_RECIPIENT

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::unique_ptr<Subscription> CallbackDeathRecipient::Register(const sptr<IRemoteObject> &remoteObj,
    DeathCallback &&callback)
{
    ENSURE_OR_RETURN_VAL(remoteObj != nullptr, nullptr);
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    sptr<CallbackDeathRecipient> recipient(new (std::nothrow) CallbackDeathRecipient(std::move(callback)));
    ENSURE_OR_RETURN_VAL(recipient != nullptr, nullptr);

#ifndef ENABLE_TEST
    if (!remoteObj->AddDeathRecipient(recipient)) {
        IAM_LOGE("AddDeathRecipient failed");
        return nullptr;
    }
    return std::make_unique<Subscription>([remoteObj, recipient]() { remoteObj->RemoveDeathRecipient(recipient); });
#else
    return std::make_unique<Subscription>([]() {});
#endif // ENABLE_TEST
}

CallbackDeathRecipient::CallbackDeathRecipient(DeathCallback &&callback) : callback_(std::move(callback))
{
}

void CallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    (void)remote;

    if (isCallbackCalled_.test_and_set()) {
        IAM_LOGI("callback already triggered, skip");
        return;
    }

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
