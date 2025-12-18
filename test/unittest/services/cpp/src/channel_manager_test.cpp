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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "channel_manager.h"
#include "mock_cross_device_channel.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class ChannelManagerTest : public Test {
public:
    void SetUp() override
    {
        mockChannel1_ = std::make_shared<NiceMock<MockCrossDeviceChannel>>();
        mockChannel2_ = std::make_shared<NiceMock<MockCrossDeviceChannel>>();
        mockChannel3_ = std::make_shared<NiceMock<MockCrossDeviceChannel>>();

        ON_CALL(*mockChannel1_, GetChannelId).WillByDefault(Return(ChannelId::SOFTBUS));
        ON_CALL(*mockChannel2_, GetChannelId).WillByDefault(Return(ChannelId::HEAD_PHONE_MANAGER));
        ON_CALL(*mockChannel3_, GetChannelId).WillByDefault(Return(ChannelId::SOFTBUS));
    }

    void TearDown() override
    {
    }

protected:
    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> mockChannel1_;
    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> mockChannel2_;
    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> mockChannel3_;
};

HWTEST_F(ChannelManagerTest, Constructor_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    channels.push_back(mockChannel1_);
    channels.push_back(nullptr);

    auto manager = std::make_shared<ChannelManager>(channels);
    EXPECT_NE(manager, nullptr);

    auto allChannels = manager->GetAllChannels();
    EXPECT_EQ(allChannels.size(), 1u);
}

HWTEST_F(ChannelManagerTest, Constructor_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;

    auto manager = std::make_shared<ChannelManager>(channels);
    EXPECT_NE(manager, nullptr);

    auto allChannels = manager->GetAllChannels();
    EXPECT_EQ(allChannels.size(), 0u);
}

HWTEST_F(ChannelManagerTest, Constructor_003, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    channels.push_back(mockChannel1_);
    channels.push_back(mockChannel3_);

    auto manager = std::make_shared<ChannelManager>(channels);
    EXPECT_NE(manager, nullptr);

    auto allChannels = manager->GetAllChannels();
    EXPECT_EQ(allChannels.size(), 1u);
}

HWTEST_F(ChannelManagerTest, GetPrimaryChannel_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    channels.push_back(mockChannel1_);
    channels.push_back(mockChannel2_);

    auto manager = std::make_shared<ChannelManager>(channels);

    auto primaryChannel = manager->GetPrimaryChannel();
    EXPECT_NE(primaryChannel, nullptr);
    EXPECT_EQ(primaryChannel->GetChannelId(), ChannelId::SOFTBUS);
}

HWTEST_F(ChannelManagerTest, GetPrimaryChannel_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;

    auto manager = std::make_shared<ChannelManager>(channels);

    auto primaryChannel = manager->GetPrimaryChannel();
    EXPECT_EQ(primaryChannel, nullptr);
}

HWTEST_F(ChannelManagerTest, GetChannelById_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    channels.push_back(mockChannel1_);

    auto manager = std::make_shared<ChannelManager>(channels);

    auto channel = manager->GetChannelById(ChannelId::SOFTBUS);
    EXPECT_NE(channel, nullptr);
    EXPECT_EQ(channel->GetChannelId(), ChannelId::SOFTBUS);
}

HWTEST_F(ChannelManagerTest, GetChannelById_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    channels.push_back(mockChannel1_);

    auto manager = std::make_shared<ChannelManager>(channels);

    auto channel = manager->GetChannelById(ChannelId::HEAD_PHONE_MANAGER);
    EXPECT_EQ(channel, nullptr);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
