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
    MOCK_METHOD(std::optional<CompanionStatus>, GetCompanionStatus, (TemplateId templateId), (override));
    MOCK_METHOD(std::optional<CompanionStatus>, GetCompanionStatus,
        (UserId hostUserId, const DeviceKey &companionDeviceKey), (override));
    MOCK_METHOD(std::vector<CompanionStatus>, GetAllCompanionStatus, (), (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeCompanionDeviceStatusChange,
        (OnCompanionDeviceStatusChange && callback), (override));
    MOCK_METHOD(void, UnsubscribeCompanionDeviceStatusChange, (SubscribeId subscriptionId), (override));
    MOCK_METHOD(ResultCode, BeginAddCompanion,
        (const BeginAddCompanionParams &params, std::vector<uint8_t> &outAddHostBindingRequest,
            uint16_t &selectedAlgorithm),
        (override));
    MOCK_METHOD(ResultCode, EndAddCompanion, (const EndAddCompanionInput &input, EndAddCompanionOutput &output),
        (override));
    MOCK_METHOD(ResultCode, RemoveCompanion, (TemplateId templateId, bool removeHostBinding), (override));
    MOCK_METHOD(ResultCode, UpdateCompanionEnabledBusinessIds,
        (TemplateId templateId, const std::vector<BusinessId> &enabledBusinessIds), (override));
    MOCK_METHOD(bool, SetCompanionTokenAuthAtl, (TemplateId templateId, std::optional<Atl> atl, bool forEnrollment),
        (override));
    MOCK_METHOD(void, StartIssueTokenRequests,
        (const std::vector<TemplateId> &templateIds, uint32_t lockStateAuthTypeValue,
            const std::vector<uint8_t> &fwkUnlockMsg),
        (override));
    MOCK_METHOD(bool, IsCapabilitySupported, (TemplateId templateId, Capability capability), (override));
    MOCK_METHOD(void, NotifyCompanionStatusChange, (), (override));
    MOCK_METHOD(void, HandleRemoveHostBindingComplete, (TemplateId templateId), (override));
    MOCK_METHOD(void, SetTemplateInvalid, (TemplateId templateId, const std::string &reason), (override));
    MOCK_METHOD(void, ReconcileWithSecurityAgent, (), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_COMPANION_MANAGER_H
