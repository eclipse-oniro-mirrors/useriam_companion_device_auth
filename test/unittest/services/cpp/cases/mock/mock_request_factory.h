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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_REQUEST_FACTORY_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_REQUEST_FACTORY_H

#include <gmock/gmock.h>

#include "request_factory.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockRequestFactory : public IRequestFactory {
public:
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateHostAddCompanionRequest,
        (uint64_t, const std::vector<uint8_t> &, uint32_t, FwkResultCallback &&), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateHostTokenAuthRequest,
        (uint64_t, const std::vector<uint8_t> &, int32_t, uint64_t, FwkResultCallback &&), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateHostRemoveHostBindingRequest, (int32_t, uint64_t, const DeviceKey &),
        (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateHostSyncDeviceStatusRequest,
        (int32_t, const DeviceKey &, const std::string &, SyncDeviceStatusCallback &&), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateHostIssueTokenRequest,
        (int32_t, uint64_t, const std::vector<uint8_t> &), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateHostDelegateAuthRequest,
        (uint64_t, const std::vector<uint8_t> &, int32_t, uint64_t, FwkResultCallback &&), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateCompanionAddCompanionRequest,
        (const std::string &, const Attributes &, OnMessageReply, const DeviceKey &), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateCompanionIssueTokenRequest,
        (const std::string &, const Attributes &, OnMessageReply, const DeviceKey &), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateHostObtainTokenRequest,
        (const std::string &, const Attributes &, OnMessageReply, const DeviceKey &), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateCompanionObtainTokenRequest,
        (const DeviceKey &, const std::vector<uint8_t> &), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateCompanionDelegateAuthRequest,
        (const std::string &, int32_t, const DeviceKey &, const std::vector<uint8_t> &), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateCompanionRevokeTokenRequest, (int32_t, const DeviceKey &), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateCompanionAuthMaintainStateChangeRequest, (const DeviceKey &, bool),
        (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateHostMixAuthRequest,
        (uint64_t, std::vector<uint8_t>, int32_t, std::vector<uint64_t>, FwkResultCallback &&), (override));
    MOCK_METHOD(std::shared_ptr<IRequest>, CreateHostSingleMixAuthRequest,
        (uint64_t, std::vector<uint8_t>, int32_t, uint64_t, FwkResultCallback &&), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_REQUEST_FACTORY_H
