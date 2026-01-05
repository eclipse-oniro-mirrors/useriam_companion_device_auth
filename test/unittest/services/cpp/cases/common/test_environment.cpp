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

#include <gtest/gtest.h>

#include "adapter_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CompanionDeviceAuthTestEnvironment : public ::testing::Environment {
public:
    ~CompanionDeviceAuthTestEnvironment() override = default;

    void SetUp() override
    {
        // Initialize all external adapters at the start of test suite
        AdapterManager::GetInstance().CreateAndRegisterAllAdapters();
    }

    void TearDown() override
    {
        // Reset adapters after all tests complete
        AdapterManager::GetInstance().Reset();
    }
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

// Automatically register the global test environment
// This will be called after gtest_main initializes GoogleTest
__attribute__((constructor)) void RegisterCompanionDeviceAuthTestEnvironment()
{
    ::testing::AddGlobalTestEnvironment(new OHOS::UserIam::CompanionDeviceAuth::CompanionDeviceAuthTestEnvironment());
}
