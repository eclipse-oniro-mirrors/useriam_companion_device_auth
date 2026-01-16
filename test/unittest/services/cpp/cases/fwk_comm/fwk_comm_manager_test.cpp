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

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "adapter_manager.h"
#include "fwk_comm_manager.h"

#include "mock_driver_manager_adapter.h"

using namespace testing;
using namespace testing::ext;

namespace {
}

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FwkCommManagerTest : public Test {
public:
    void SetUp() override
    {
        // Initialize DriverManagerAdapter mock
        auto driverManagerAdapter =
            std::shared_ptr<IDriverManagerAdapter>(&mockDriverManagerAdapter_, [](IDriverManagerAdapter *) {});
        AdapterManager::GetInstance().SetDriverManagerAdapter(driverManagerAdapter);
        ON_CALL(mockDriverManagerAdapter_, Start(_)).WillByDefault(Return(true));
    }

    void TearDown() override
    {
#ifdef ENABLE_TEST
        AdapterManager::GetInstance().Reset();
#endif
    }

protected:
    NiceMock<MockDriverManagerAdapter> mockDriverManagerAdapter_;
};

HWTEST_F(FwkCommManagerTest, Create_001, TestSize.Level0)
{
    auto manager = FwkCommManager::Create();
    EXPECT_NE(nullptr, manager);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
