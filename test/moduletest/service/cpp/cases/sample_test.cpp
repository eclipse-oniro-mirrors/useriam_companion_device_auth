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

namespace OHOS::UserIAM::CompanionDeviceAuth {

class SampleModuleTest : public testing::Test {
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

TEST_F(SampleModuleTest, BasicTest)
{
    // Sample module test
    EXPECT_TRUE(true);
}

TEST_F(SampleModuleTest, AnotherTest)
{
    // Another sample test
    int result = 1 + 1;
    int expectResult = 2;
    EXPECT_EQ(result, expectResult);
}

} // namespace OHOS::UserIAM::CompanionDeviceAuth
