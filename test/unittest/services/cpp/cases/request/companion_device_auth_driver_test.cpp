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

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "attributes.h"
#include "companion_auth_interface_adapter.h"
#include "companion_device_auth_driver.h"
#include "fwk_common.h"
#include "service_common.h"
#include "singleton_manager.h"

#include "mock_companion_manager.h"
#include "mock_host_binding_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_user_id_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CompanionDeviceAuthDriverTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        adapter_ = std::make_shared<CompanionAuthInterfaceAdapter>();

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto requestFactory = std::shared_ptr<IRequestFactory>(&mockRequestFactory_, [](IRequestFactory *) {});
        SingletonManager::GetInstance().SetRequestFactory(requestFactory);

        auto requestManager = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestManager);

        auto companionManager = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionManager);

        auto hostBindingManager = std::shared_ptr<IHostBindingManager>(&mockHostBindingManager_,
            [](IHostBindingManager *) {});
        SingletonManager::GetInstance().SetHostBindingManager(hostBindingManager);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto activeUserIdMgr = std::shared_ptr<IUserIdManager>(&mockUserIdManager_, [](IUserIdManager *) {});
        SingletonManager::GetInstance().SetActiveUserIdManager(activeUserIdMgr);

        uint32_t maxTemplateAcl = 3;
        ON_CALL(mockSecurityAgent_, HostGetExecutorInfo(_)).WillByDefault(Invoke(
            [maxTemplateAcl](HostGetExecutorInfoOutput &output) {
                output.executorInfo.esl = 1;
                output.executorInfo.maxTemplateAcl = maxTemplateAcl;
                output.executorInfo.publicKey = { 1, 2, 3 };
                return ResultCode::SUCCESS;
            }));
        ON_CALL(mockSecurityAgent_, HostOnRegisterFinish(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockUserIdManager_, SubscribeActiveUserId(_)).WillByDefault(Invoke(
            [](ActiveUserIdCallback &&) {
                return std::make_unique<Subscription>([] {});
            }));
    }

    void TearDown() override
    {
        SingletonManager::GetInstance().Reset();
        adapter_.reset();
    }

protected:
    std::shared_ptr<CompanionAuthInterfaceAdapter> adapter_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockUserIdManager> mockUserIdManager_;
};

HWTEST_F(CompanionDeviceAuthDriverTest, Constructor_001, TestSize.Level0)
{
    auto driver = std::make_unique<CompanionDeviceAuthDriver>(adapter_);
    EXPECT_NE(nullptr, driver);
}

HWTEST_F(CompanionDeviceAuthDriverTest, GetExecutorList_001, TestSize.Level0)
{
    auto driver = std::make_unique<CompanionDeviceAuthDriver>(adapter_);
    ASSERT_NE(nullptr, driver);

    std::vector<std::shared_ptr<FwkIAuthExecutorHdi>> executorList;
    driver->GetExecutorList(executorList);

    EXPECT_EQ(1u, executorList.size());
    EXPECT_NE(nullptr, executorList[0]);
}

HWTEST_F(CompanionDeviceAuthDriverTest, OnHdiDisconnect_001, TestSize.Level0)
{
    auto driver = std::make_unique<CompanionDeviceAuthDriver>(adapter_);
    ASSERT_NE(nullptr, driver);

    driver->OnHdiDisconnect();
    EXPECT_TRUE(true);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
