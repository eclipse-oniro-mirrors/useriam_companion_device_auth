/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "sa_manager_adapter_impl.h"

#include "iservice_registry.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "if_system_ability_manager.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002510
#undef LOG_TAG
#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

bool SaManagerAdapterImpl::SubscribeSystemAbility(int32_t systemAbilityId,
    const sptr<SystemAbilityStatusChangeStub> &listener)
{
    if (systemAbilityId < 0) {
        IAM_LOGE("Invalid SA ID: %{public}d", systemAbilityId);
        return false;
    }

    if (listener == nullptr) {
        IAM_LOGE("Listener is null");
        return false;
    }

    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("Failed to get SystemAbilityManager");
        return false;
    }

    // Subscribe requires non-const reference, create a copy
    sptr<SystemAbilityStatusChangeStub> listenerCopy = listener;
    int32_t ret = sam->SubscribeSystemAbility(systemAbilityId, listenerCopy);
    if (ret != 0) {
        IAM_LOGE("SubscribeSystemAbility failed, ret=%{public}d", ret);
        return false;
    }

    IAM_LOGI("Subscribed to SA ID=%{public}d", systemAbilityId);
    return true;
}

bool SaManagerAdapterImpl::UnSubscribeSystemAbility(int32_t systemAbilityId,
    const sptr<SystemAbilityStatusChangeStub> &listener)
{
    if (systemAbilityId < 0) {
        IAM_LOGE("Invalid SA ID: %{public}d", systemAbilityId);
        return false;
    }

    if (listener == nullptr) {
        IAM_LOGE("Listener is null");
        return false;
    }

    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGW("Failed to get SAM");
        return false;
    }

    // UnSubscribe requires non-const reference, create a copy
    sptr<SystemAbilityStatusChangeStub> listenerCopy = listener;
    int32_t ret = sam->UnSubscribeSystemAbility(systemAbilityId, listenerCopy);
    if (ret != ERR_OK) {
        IAM_LOGE("UnSubscribeSystemAbility failed, ret=%{public}d", ret);
        return false;
    }

    IAM_LOGI("Unsubscribed from SA ID=%{public}d", systemAbilityId);
    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
