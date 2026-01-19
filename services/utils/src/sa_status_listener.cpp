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

#include "sa_status_listener.h"

#include <memory>
#include <new>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "if_system_ability_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SaStatusListener::SaStatusStub final : public SystemAbilityStatusChangeStub {
public:
    using AddFunc = std::function<void(void)>;
    using RemoveFunc = std::function<void(void)>;

    SaStatusStub(int32_t systemAbilityId, AddFunc &&addFunc, RemoveFunc &&removeFunc);
    ~SaStatusStub() override = default;

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    int32_t systemAbilityId_ = -1;
    AddFunc addFunc_;
    RemoveFunc removeFunc_;
};

SaStatusListener::SaStatusStub::SaStatusStub(int32_t systemAbilityId, AddFunc &&addFunc, RemoveFunc &&removeFunc)
    : systemAbilityId_(systemAbilityId),
      addFunc_(std::move(addFunc)),
      removeFunc_(std::move(removeFunc))
{
}

void SaStatusListener::SaStatusStub::OnAddSystemAbility(int32_t systemAbilityId,
    [[maybe_unused]] const std::string &deviceId)
{
    ENSURE_OR_RETURN(systemAbilityId == systemAbilityId_);
    ENSURE_OR_RETURN(addFunc_ != nullptr);
    IAM_LOGI("OnAddSystemAbility %{public}d", systemAbilityId);

    TaskRunnerManager::GetInstance().PostTaskOnResident([addFunc = addFunc_]() { addFunc(); });
}

void SaStatusListener::SaStatusStub::OnRemoveSystemAbility(int32_t systemAbilityId,
    [[maybe_unused]] const std::string &deviceId)
{
    ENSURE_OR_RETURN(systemAbilityId == systemAbilityId_);
    ENSURE_OR_RETURN(removeFunc_ != nullptr);
    IAM_LOGI("OnRemoveSystemAbility %{public}d", systemAbilityId);

    TaskRunnerManager::GetInstance().PostTaskOnResident([removeFunc = removeFunc_]() { removeFunc(); });
}

std::unique_ptr<SaStatusListener> SaStatusListener::Create(const std::string &name, int32_t systemAbilityId,
    AddFunc &&addFunc, RemoveFunc &&removeFunc)
{
#ifndef ENABLE_TEST
    std::unique_ptr<SaStatusListener> listener(
        new (std::nothrow) SaStatusListener(name, systemAbilityId, std::move(addFunc), std::move(removeFunc)));
    ENSURE_OR_RETURN_VAL(listener != nullptr, nullptr);

    if (!listener->Subscribe()) {
        IAM_LOGE("subscribe failed");
        return nullptr;
    }
    return listener;
#else
    (void)name;
    (void)systemAbilityId;
    (void)addFunc;
    (void)removeFunc;
    return nullptr;
#endif // ENABLE_TEST
}

SaStatusListener::SaStatusListener([[maybe_unused]] const std::string &name, int32_t systemAbilityId, AddFunc &&addFunc,
    RemoveFunc &&removeFunc)
    : systemAbilityId_(systemAbilityId),
      stub_(new(std::nothrow) SaStatusStub(systemAbilityId, std::move(addFunc), std::move(removeFunc)))
{
}

SaStatusListener::~SaStatusListener()
{
    Unsubscribe();
}

bool SaStatusListener::Subscribe()
{
    ENSURE_OR_RETURN_VAL(stub_ != nullptr, false);

    if (!GetSaManagerAdapter().SubscribeSystemAbility(systemAbilityId_, stub_)) {
        IAM_LOGE("SubscribeSystemAbility failed");
        return false;
    }

    IAM_LOGI("subscribed to SA %{public}d", systemAbilityId_);
    return true;
}

void SaStatusListener::Unsubscribe()
{
    ENSURE_OR_RETURN(stub_ != nullptr);

    if (!GetSaManagerAdapter().UnSubscribeSystemAbility(systemAbilityId_, stub_)) {
        IAM_LOGW("UnSubscribeSystemAbility failed for SA %{public}d", systemAbilityId_);
    }

    stub_ = nullptr;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
