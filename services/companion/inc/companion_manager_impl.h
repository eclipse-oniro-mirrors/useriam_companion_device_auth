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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_MANAGER_IMPL_H
#define COMPANION_DEVICE_AUTH_COMPANION_MANAGER_IMPL_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "companion.h"
#include "service_common.h"
#include "singleton.h"
#include "singleton_manager.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CompanionManagerImpl : public ICompanionManager, public std::enable_shared_from_this<CompanionManagerImpl> {
public:
    static std::shared_ptr<CompanionManagerImpl> Create();

    ~CompanionManagerImpl() override;

    void Reload(const std::vector<PersistedCompanionStatus> &persistedCompanionList) override;

    std::optional<CompanionStatus> GetCompanionStatus(TemplateId templateId) override;
    std::optional<CompanionStatus> GetCompanionStatus(UserId hostUserId, const DeviceKey &companionDeviceKey) override;
    std::vector<CompanionStatus> GetAllCompanionStatus() override;

    std::unique_ptr<Subscription> SubscribeCompanionDeviceStatusChange(
        OnCompanionDeviceStatusChange &&callback) override;
    void UnsubscribeCompanionDeviceStatusChange(SubscribeId subscriptionId) override;

    ResultCode BeginAddCompanion(const BeginAddCompanionParams &params,
        std::vector<uint8_t> &outAddHostBindingRequest) override;
    ResultCode EndAddCompanion(const EndAddCompanionInputParam &inputParam,
        std::vector<uint8_t> &outFwkMsg, std::vector<uint8_t> &outTokenData, Atl &outAtl) override;
    ResultCode ActivateToken(RequestId requestId, TemplateId templateId, Atl atl) override;
    ResultCode RemoveCompanion(TemplateId templateId) override;

    ResultCode UpdateCompanionStatus(TemplateId templateId, const std::string &deviceName,
        const std::string &deviceUserName) override;
    ResultCode UpdateCompanionEnabledBusinessIds(TemplateId templateId,
        const std::vector<BusinessIdType> &enabledBusinessIds) override;
    bool SetCompanionTokenAtl(TemplateId templateId, std::optional<Atl> atl) override;
    ResultCode UpdateToken(TemplateId templateId, const std::vector<uint8_t> &fwkMsg, bool &needRedistribute) override;

    ResultCode HandleCompanionCheckFail(TemplateId templateId) override;

    void StartIssueTokenRequests(const std::vector<TemplateId> &templateIds,
        const std::vector<uint8_t> &fwkUnlockMsg) override;
    void RevokeTokens(const std::vector<TemplateId> &templateIds) override;

    void NotifyCompanionStatusChange() override;

#ifndef ENABLE_TEST
private:
#endif
    CompanionManagerImpl();
    void Initialize() override;
    void OnActiveUserIdChanged(UserId userId);

    std::shared_ptr<Companion> FindCompanionByTemplateId(TemplateId templateId);
    std::shared_ptr<Companion> FindCompanionByDeviceUser(UserId hostUserId, const DeviceKey &deviceKey);

    ResultCode AddCompanionInternal(const std::shared_ptr<Companion> &companion);
    ResultCode RemoveCompanionInternal(TemplateId templateId);

    UserId hostUserId_ { INVALID_USER_ID };
    std::vector<std::shared_ptr<Companion>> companions_;

    std::map<SubscribeId, OnCompanionDeviceStatusChange> statusSubscribers_;
    std::atomic<SubscribeId> nextSubscriptionId_ { 1 };

    std::unique_ptr<Subscription> activeUserIdSubscription_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_MANAGER_IMPL_H
