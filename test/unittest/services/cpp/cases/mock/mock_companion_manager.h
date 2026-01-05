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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_COMPANION_MANAGER_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_COMPANION_MANAGER_H

#include <gmock/gmock.h>

#include "companion_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockCompanionManager : public ICompanionManager {
public:
    MOCK_METHOD(void, Reload, (const std::vector<PersistedCompanionStatus> &persistedCompanionList), (override));
    MOCK_METHOD(std::optional<CompanionStatus>, GetCompanionStatus, (TemplateId templateId), (override));
    MOCK_METHOD(std::optional<CompanionStatus>, GetCompanionStatus,
        (UserId hostUserId, const DeviceKey &companionDeviceKey), (override));
    MOCK_METHOD(std::vector<CompanionStatus>, GetAllCompanionStatus, (), (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeCompanionDeviceStatusChange,
        (OnCompanionDeviceStatusChange && callback), (override));
    MOCK_METHOD(void, UnsubscribeCompanionDeviceStatusChange, (SubscribeId subscriptionId), (override));
    MOCK_METHOD(ResultCode, BeginAddCompanion,
        (const BeginAddCompanionParams &params, std::vector<uint8_t> &outAddHostBindingRequest), (override));
    MOCK_METHOD(ResultCode, EndAddCompanion,
        (const EndAddCompanionInputParam &inputParam, std::vector<uint8_t> &outFwkMsg,
            std::vector<uint8_t> &outTokenData, Atl &outAtl),
        (override));
    MOCK_METHOD(ResultCode, ActivateToken, (RequestId requestId, TemplateId templateId, Atl atl), (override));
    MOCK_METHOD(ResultCode, RemoveCompanion, (TemplateId templateId), (override));
    MOCK_METHOD(ResultCode, UpdateCompanionStatus,
        (TemplateId templateId, const std::string &deviceName, const std::string &deviceUserName), (override));
    MOCK_METHOD(ResultCode, UpdateCompanionEnabledBusinessIds,
        (TemplateId templateId, const std::vector<BusinessIdType> &enabledBusinessIds), (override));
    MOCK_METHOD(bool, SetCompanionTokenAtl, (TemplateId templateId, std::optional<Atl> atl), (override));
    MOCK_METHOD(ResultCode, UpdateToken,
        (TemplateId templateId, const std::vector<uint8_t> &fwkMsg, bool &needRedistribute), (override));
    MOCK_METHOD(ResultCode, HandleCompanionCheckFail, (TemplateId templateId), (override));
    MOCK_METHOD(void, StartIssueTokenRequests,
        (const std::vector<TemplateId> &templateIds, const std::vector<uint8_t> &fwkUnlockMsg), (override));
    MOCK_METHOD(void, RevokeTokens, (const std::vector<TemplateId> &templateIds), (override));
    MOCK_METHOD(void, NotifyCompanionStatusChange, (), (override));
    MOCK_METHOD(void, Initialize, (), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_COMPANION_MANAGER_H
