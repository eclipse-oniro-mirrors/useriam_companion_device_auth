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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "channel_manager.h"
#include "common_defines.h"
#include "connection_manager.h"
#include "cross_device_comm/cross_device_common.h"
#include "cross_device_comm/icross_device_channel.h"
#include "local_device_status_manager.h"
#include "message_router.h"
#include "misc/active_user_id_manager.h"
#include "misc/misc_manager.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class FakeMiscManager : public IMiscManager {
public:
    int32_t GetNextGlobalId() override
    {
        return nextGlobalId_++;
    }

    bool SetDeviceSelectCallback(uint32_t, const sptr<IIpcDeviceSelectCallback> &) override
    {
        return true;
    }

    bool GetDeviceDeviceSelectResult(uint32_t, SelectPurpose, DeviceSelectResultHandler &&) override
    {
        return true;
    }

    void ClearDeviceSelectCallback(uint32_t) override
    {
    }

    std::optional<std::string> GetLocalUdid() override
    {
        return std::string("local-udid");
    }

    uint32_t GetAccessTokenId(IPCObjectStub &) override
    {
        return 0;
    }

private:
    int32_t nextGlobalId_ { 1 };
};

class FakeActiveUserIdManager : public IActiveUserIdManager {
public:
    bool Initialize() override
    {
        return true;
    }

    int32_t GetActiveUserId() const override
    {
        return activeUserId_;
    }

    std::string GetActiveUserName() const override
    {
        return "tester";
    }

    std::unique_ptr<Subscription> SubscribeActiveUserId(ActiveUserIdCallback &&callback) override
    {
        activeUserIdCallback_ = std::move(callback);
        return std::make_unique<Subscription>([]() {});
    }

private:
    int32_t activeUserId_ { 100 };
    ActiveUserIdCallback activeUserIdCallback_ {};
};

class FakeCrossDeviceChannel : public ICrossDeviceChannel {
public:
    explicit FakeCrossDeviceChannel(ChannelId channelId) : channelId_(channelId)
    {
        localPhysicalKey_.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        localPhysicalKey_.deviceId = "local-device";
    }

    bool Start() override
    {
        return true;
    }

    ChannelId GetChannelId() const override
    {
        return channelId_;
    }

    PhysicalDeviceKey GetLocalPhysicalDeviceKey() const override
    {
        return localPhysicalKey_;
    }

    bool OpenConnection(const std::string &connectionName, const PhysicalDeviceKey &) override
    {
        openedConnections_.push_back(connectionName);
        return true;
    }

    void CloseConnection(const std::string &connectionName) override
    {
        closedConnections_.push_back(connectionName);
    }

    bool SendMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg) override
    {
        lastSendConnection_ = connectionName;
        sentMessages_.push_back(rawMsg);
        return true;
    }

    std::unique_ptr<Subscription> SubscribePhysicalDeviceStatus(OnPhysicalDeviceStatusChange &&callback) override
    {
        physicalDeviceStatusCallback_ = std::move(callback);
        return std::make_unique<Subscription>([]() {});
    }

    std::vector<PhysicalDeviceStatus> GetAllPhysicalDevices() const override
    {
        return {};
    }

    std::unique_ptr<Subscription> SubscribeRawMessage(OnRawMessage &&callback) override
    {
        rawMessageCallback_ = std::move(callback);
        return std::make_unique<Subscription>([]() {});
    }

    std::unique_ptr<Subscription> SubscribeConnectionStatus(OnConnectionStatusChange &&callback) override
    {
        connectionStatusCallback_ = std::move(callback);
        return std::make_unique<Subscription>([]() {});
    }

    std::unique_ptr<Subscription> SubscribeIncomingConnection(OnIncomingConnection &&callback) override
    {
        incomingConnectionCallback_ = std::move(callback);
        return std::make_unique<Subscription>([]() {});
    }

    bool GetAuthMaintainActive() const override
    {
        return isAuthMaintainActive_;
    }

    std::unique_ptr<Subscription> SubscribeAuthMaintainActive(OnAuthMaintainActiveChange &&callback) override
    {
        authMaintainCallback_ = std::move(callback);
        return std::make_unique<Subscription>([]() {});
    }

    SecureProtocolId GetcompanionSecureProtocolId() const override
    {
        return SecureProtocolId::DEFAULT;
    }

    bool CheckOperationIntent(const DeviceKey &, uint32_t, OnCheckOperationIntentResult &&resultCallback) override
    {
        if (resultCallback != nullptr) {
            resultCallback(true);
        }
        return true;
    }

    const std::vector<std::vector<uint8_t>> &GetSentMessages() const
    {
        return sentMessages_;
    }

    void TriggerRawMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg)
    {
        if (rawMessageCallback_ != nullptr) {
            rawMessageCallback_(connectionName, rawMsg);
        }
    }

private:
    ChannelId channelId_ { ChannelId::INVALID };
    PhysicalDeviceKey localPhysicalKey_ {};
    OnPhysicalDeviceStatusChange physicalDeviceStatusCallback_ {};
    OnRawMessage rawMessageCallback_ {};
    OnConnectionStatusChange connectionStatusCallback_ {};
    OnIncomingConnection incomingConnectionCallback_ {};
    OnAuthMaintainActiveChange authMaintainCallback_ {};
    bool isAuthMaintainActive_ { false };
    std::string lastSendConnection_ {};
    std::vector<std::string> openedConnections_ {};
    std::vector<std::string> closedConnections_ {};
    std::vector<std::vector<uint8_t>> sentMessages_ {};
};

class MessageRouterTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        SingletonManager::GetInstance().SetMiscManager(std::make_shared<FakeMiscManager>());
        SingletonManager::GetInstance().SetActiveUserIdManager(std::make_shared<FakeActiveUserIdManager>());
    }

    void SetUp() override
    {
        channel_ = std::make_shared<FakeCrossDeviceChannel>(ChannelId::SOFTBUS);
        channelManager_ =
            std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> { channel_ });
        localDeviceStatusManager_ = LocalDeviceStatusManager::Create(channelManager_);
        ASSERT_NE(localDeviceStatusManager_, nullptr);

        connectionManager_ = ConnectionManager::Create(channelManager_, localDeviceStatusManager_);
        ASSERT_NE(connectionManager_, nullptr);

        router_ = MessageRouter::Create(connectionManager_, channelManager_);
        ASSERT_NE(router_, nullptr);

        PhysicalDeviceKey physicalDeviceKey;
        physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        physicalDeviceKey.deviceId = "remote-device";
        ASSERT_TRUE(connectionManager_->HandleIncomingConnection(connectionName_, physicalDeviceKey));
    }

protected:
    std::string connectionName_ { "test-connection" };
    std::shared_ptr<FakeCrossDeviceChannel> channel_;
    std::shared_ptr<ChannelManager> channelManager_;
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusManager_;
    std::shared_ptr<ConnectionManager> connectionManager_;
    std::shared_ptr<MessageRouter> router_;
};

HWTEST_F(MessageRouterTest, SendMessage_001, TestSize.Level1)
{
    Attributes request;
    bool replyReceived = false;
    int32_t replyCode = -1;

    bool sendResult = router_->SendMessage(connectionName_, MessageType::KEEP_ALIVE, request,
        [&replyReceived, &replyCode](const Attributes &reply) {
            replyReceived = true;
            (void)reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyCode);
        });
    ASSERT_TRUE(sendResult);
    ASSERT_FALSE(channel_->GetSentMessages().empty());

    Attributes sentMessage(channel_->GetSentMessages().back());
    uint32_t messageSeq = 0;
    ASSERT_TRUE(sentMessage.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, messageSeq));
    bool isReply = true;
    ASSERT_TRUE(sentMessage.GetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, isReply));
    EXPECT_FALSE(isReply);
    uint32_t msgTypeValue = 0;
    ASSERT_TRUE(sentMessage.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_TYPE, msgTypeValue));

    Attributes reply;
    reply.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    reply.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, messageSeq);
    reply.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, true);
    reply.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_TYPE, msgTypeValue);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(SaResultCode::SUCCESS));

    channel_->TriggerRawMessage(connectionName_, reply.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(replyReceived);
    EXPECT_EQ(static_cast<int32_t>(SaResultCode::SUCCESS), replyCode);
}

HWTEST_F(MessageRouterTest, SendMessage_002, TestSize.Level0)
{
    Attributes request;

    bool sendResult = router_->SendMessage("non-existent-connection", MessageType::KEEP_ALIVE, request, nullptr);
    EXPECT_FALSE(sendResult);
}

HWTEST_F(MessageRouterTest, SendMessage_003, TestSize.Level0)
{
    Attributes request;

    bool sendResult = router_->SendMessage(connectionName_, MessageType::KEEP_ALIVE, request, nullptr);
    EXPECT_TRUE(sendResult);
}

HWTEST_F(MessageRouterTest, SubscribeMessage_001, TestSize.Level0)
{
    bool messageReceived = false;
    auto subscription = router_->SubscribeMessage(connectionName_, MessageType::TOKEN_AUTH,
        [&messageReceived](const Attributes &, OnMessageReply &) { messageReceived = true; });
    EXPECT_NE(subscription, nullptr);

    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint32_t>(MessageType::TOKEN_AUTH));

    channel_->TriggerRawMessage(connectionName_, msg.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(messageReceived);
}

HWTEST_F(MessageRouterTest, SubscribeMessage_002, TestSize.Level0)
{
    bool messageReceived = false;
    {
        auto subscription = router_->SubscribeMessage(connectionName_, MessageType::TOKEN_AUTH,
            [&messageReceived](const Attributes &, OnMessageReply &) { messageReceived = true; });
        EXPECT_NE(subscription, nullptr);
    }

    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint32_t>(MessageType::TOKEN_AUTH));

    channel_->TriggerRawMessage(connectionName_, msg.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(messageReceived);
}

HWTEST_F(MessageRouterTest, SubscribeIncomingConnection_001, TestSize.Level0)
{
    bool messageReceived = false;
    auto subscription = router_->SubscribeIncomingConnection(MessageType::START_DELEGATE_AUTH,
        [&messageReceived](const Attributes &, OnMessageReply &) { messageReceived = true; });
    EXPECT_NE(subscription, nullptr);

    std::string newConnectionName = "new-incoming-connection";
    PhysicalDeviceKey physicalDeviceKey;
    physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    physicalDeviceKey.deviceId = "new-remote-device";
    ASSERT_TRUE(connectionManager_->HandleIncomingConnection(newConnectionName, physicalDeviceKey));

    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, newConnectionName);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint32_t>(MessageType::START_DELEGATE_AUTH));

    channel_->TriggerRawMessage(newConnectionName, msg.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(messageReceived);
}

HWTEST_F(MessageRouterTest, SubscribeIncomingConnection_002, TestSize.Level0)
{
    bool messageReceived = false;
    {
        auto subscription = router_->SubscribeIncomingConnection(MessageType::START_DELEGATE_AUTH,
            [&messageReceived](const Attributes &, OnMessageReply &) { messageReceived = true; });
        EXPECT_NE(subscription, nullptr);
    }

    std::string newConnectionName = "new-incoming-connection-2";
    PhysicalDeviceKey physicalDeviceKey;
    physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    physicalDeviceKey.deviceId = "new-remote-device-2";
    ASSERT_TRUE(connectionManager_->HandleIncomingConnection(newConnectionName, physicalDeviceKey));

    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, newConnectionName);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint32_t>(MessageType::START_DELEGATE_AUTH));

    channel_->TriggerRawMessage(newConnectionName, msg.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(messageReceived);
}

HWTEST_F(MessageRouterTest, Create_001, TestSize.Level0)
{
    auto router = MessageRouter::Create(connectionManager_, channelManager_);
    EXPECT_NE(router, nullptr);
}

HWTEST_F(MessageRouterTest, Create_002, TestSize.Level0)
{
    auto router = MessageRouter::Create(nullptr, channelManager_);
    EXPECT_EQ(router, nullptr);
}

HWTEST_F(MessageRouterTest, HandleRawMessage_001, TestSize.Level0)
{
    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 999);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint32_t>(MessageType::TOKEN_AUTH));

    router_->HandleRawMessage(connectionName_, msg.Serialize());
}

HWTEST_F(MessageRouterTest, HandleRawMessage_002, TestSize.Level0)
{
    std::vector<uint8_t> invalidMsg = { 0x01, 0x02, 0x03 };
    router_->HandleRawMessage(connectionName_, invalidMsg);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
