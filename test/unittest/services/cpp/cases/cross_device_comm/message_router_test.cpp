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
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "adapter_manager.h"
#include "channel_manager.h"
#include "common_defines.h"
#include "connection_manager.h"
#include "cross_device_comm/cross_device_common.h"
#include "cross_device_comm/icross_device_channel.h"
#include "local_device_status_manager.h"
#include "message_router.h"
#include "misc/misc_manager.h"
#include "mock_time_keeper.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "time_keeper.h"
#include "user_id_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr uint64_t UINT64_INITIAL_GLOBAL_ID = 1;
constexpr int32_t INT32_TEST_ACTIVE_USER_ID = 100;
constexpr uint32_t UINT32_TEST_INVALID_MESSAGE_SEQ = 99999;
constexpr uint32_t UINT32_TEST_INVALID_MESSAGE_SEQ_ALT = 999;
constexpr int32_t INT32_TEST_TIMEOUT_OFFSET_MS = 6000;

inline std::vector<uint8_t> GetTestInvalidMessageBytes()
{
    return { 0x01, 0x02, 0x03 };
}

class FakeMiscManager : public IMiscManager {
public:
    uint64_t GetNextGlobalId() override
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

    bool CheckBusinessIds(const std::vector<BusinessId> &)
    {
        return true;
    }

private:
    uint64_t nextGlobalId_ { UINT64_INITIAL_GLOBAL_ID };
};

class FakeUserIdManager : public IUserIdManager {
public:
    bool Initialize()
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

    bool IsUserIdValid(int32_t userId) override
    {
        return userId == activeUserId_;
    }

private:
    int32_t activeUserId_ { INT32_TEST_ACTIVE_USER_ID };
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

    std::optional<PhysicalDeviceKey> GetLocalPhysicalDeviceKey() const override
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

    SecureProtocolId GetCompanionSecureProtocolId() const override
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

    bool RequiresDisconnectNotification() const override
    {
        return false;
    }

    void OnRemoteDisconnect(const std::string &, const std::string &) override
    {
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

        staticTimeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(staticTimeKeeper);

        AdapterManager::GetInstance().SetUserIdManager(std::make_shared<FakeUserIdManager>());
    }

    static void TearDownTestCase()
    {
        AdapterManager::GetInstance().Reset();
    }

    void SetUp() override
    {
        // Use the static timeKeeper for tests
        timeKeeper_ = staticTimeKeeper;
        ASSERT_NE(timeKeeper_, nullptr);

        channel_ = std::make_shared<FakeCrossDeviceChannel>(ChannelId::SOFTBUS);
        channelManager_ =
            std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> { channel_ });
        localDeviceStatusManager_ = LocalDeviceStatusManager::Create(channelManager_,
            { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
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
    static std::shared_ptr<MockTimeKeeper> staticTimeKeeper;
    std::string connectionName_ { "test-connection" };
    std::shared_ptr<MockTimeKeeper> timeKeeper_;
    std::shared_ptr<FakeCrossDeviceChannel> channel_;
    std::shared_ptr<ChannelManager> channelManager_;
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusManager_;
    std::shared_ptr<ConnectionManager> connectionManager_;
    std::shared_ptr<MessageRouter> router_;
};

std::shared_ptr<MockTimeKeeper> MessageRouterTest::staticTimeKeeper = nullptr;

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
    uint16_t msgTypeValue = 0;
    ASSERT_TRUE(sentMessage.GetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, msgTypeValue));

    Attributes reply;
    reply.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    reply.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, messageSeq);
    reply.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, true);
    reply.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, msgTypeValue);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    channel_->TriggerRawMessage(connectionName_, reply.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(replyReceived);
    EXPECT_EQ(static_cast<int32_t>(ResultCode::SUCCESS), replyCode);
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

HWTEST_F(MessageRouterTest, SendMessage_004, TestSize.Level0)
{
    Attributes request;

    bool replyReceived = false;
    bool sendResult = router_->SendMessage(connectionName_, MessageType::KEEP_ALIVE, request,
        [&replyReceived](const Attributes &) { replyReceived = true; });
    EXPECT_TRUE(sendResult);

    Attributes sentMessage(channel_->GetSentMessages().back());
    uint32_t messageSeq = 0;
    ASSERT_TRUE(sentMessage.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, messageSeq));

    Attributes reply;
    reply.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    reply.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, UINT32_TEST_INVALID_MESSAGE_SEQ);
    reply.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, true);
    reply.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::KEEP_ALIVE));

    channel_->TriggerRawMessage(connectionName_, reply.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(replyReceived);
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
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::TOKEN_AUTH));

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
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::TOKEN_AUTH));

    channel_->TriggerRawMessage(connectionName_, msg.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(messageReceived);
}

HWTEST_F(MessageRouterTest, SubscribeMessage_003, TestSize.Level0)
{
    bool firstCallbackInvoked = false;
    bool secondCallbackInvoked = false;

    auto subscription1 = router_->SubscribeMessage(connectionName_, MessageType::TOKEN_AUTH,
        [&firstCallbackInvoked](const Attributes &, OnMessageReply &) { firstCallbackInvoked = true; });

    auto subscription2 = router_->SubscribeMessage(connectionName_, MessageType::TOKEN_AUTH,
        [&secondCallbackInvoked](const Attributes &, OnMessageReply &) { secondCallbackInvoked = true; });

    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::TOKEN_AUTH));

    channel_->TriggerRawMessage(connectionName_, msg.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(firstCallbackInvoked);
    EXPECT_TRUE(secondCallbackInvoked);
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
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::START_DELEGATE_AUTH));

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
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::START_DELEGATE_AUTH));

    channel_->TriggerRawMessage(newConnectionName, msg.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(messageReceived);
}

HWTEST_F(MessageRouterTest, SubscribeIncomingConnection_003, TestSize.Level0)
{
    bool messageReceived = false;
    auto subscription = router_->SubscribeIncomingConnection(MessageType::TOKEN_AUTH,
        [&messageReceived](const Attributes &, OnMessageReply &) { messageReceived = true; });

    std::string newConnectionName = "new-conn";
    PhysicalDeviceKey physicalDeviceKey;
    physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    physicalDeviceKey.deviceId = "new-device";
    ASSERT_TRUE(connectionManager_->HandleIncomingConnection(newConnectionName, physicalDeviceKey));

    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, newConnectionName);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::START_DELEGATE_AUTH));

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

HWTEST_F(MessageRouterTest, Create_003, TestSize.Level0)
{
    auto router = MessageRouter::Create(connectionManager_, nullptr);
    EXPECT_EQ(router, nullptr);
}

HWTEST_F(MessageRouterTest, HandleRawMessage_001, TestSize.Level0)
{
    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, UINT32_TEST_INVALID_MESSAGE_SEQ_ALT);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::TOKEN_AUTH));

    router_->HandleRawMessage(connectionName_, msg.Serialize());
}

HWTEST_F(MessageRouterTest, HandleRawMessage_002, TestSize.Level0)
{
    std::vector<uint8_t> invalidMsg = GetTestInvalidMessageBytes();
    router_->HandleRawMessage(connectionName_, invalidMsg);
}

HWTEST_F(MessageRouterTest, HandleRawMessage_003, TestSize.Level0)
{
    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "non-existent-connection");
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::TOKEN_AUTH));

    channel_->TriggerRawMessage("non-existent-connection", msg.Serialize());
}

HWTEST_F(MessageRouterTest, HandleRequest_001, TestSize.Level0)
{
    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::DISCONNECT));
    msg.SetStringValue(Attributes::ATTR_CDA_SA_REASON, "test_disconnect");

    channel_->TriggerRawMessage(connectionName_, msg.Serialize());
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(MessageRouterTest, HandleRequest_002, TestSize.Level0)
{
    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::DISCONNECT));

    channel_->TriggerRawMessage(connectionName_, msg.Serialize());
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(MessageRouterTest, HandleRequest_003, TestSize.Level0)
{
    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::TOKEN_AUTH));

    channel_->TriggerRawMessage(connectionName_, msg.Serialize());
    TaskRunnerManager::GetInstance().ExecuteAll();

    ASSERT_FALSE(channel_->GetSentMessages().empty());
}

HWTEST_F(MessageRouterTest, HandleRequest_004, TestSize.Level0)
{
    bool messageReceived = false;
    bool replySent = false;
    auto subscription = router_->SubscribeMessage(connectionName_, MessageType::TOKEN_AUTH,
        [&messageReceived, &replySent](const Attributes &request, OnMessageReply &onReply) {
            messageReceived = true;
            if (onReply != nullptr) {
                Attributes reply;
                reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
                onReply(reply);
                replySent = true;
            }
        });

    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::TOKEN_AUTH));

    channel_->TriggerRawMessage(connectionName_, msg.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(messageReceived);
    EXPECT_TRUE(replySent);
}

HWTEST_F(MessageRouterTest, FindMessageSubscriber_001, TestSize.Level0)
{
    bool connSpecificInvoked = false;
    bool incomingInvoked = false;

    auto subscription1 = router_->SubscribeIncomingConnection(MessageType::TOKEN_AUTH,
        [&incomingInvoked](const Attributes &, OnMessageReply &) { incomingInvoked = true; });

    auto subscription2 = router_->SubscribeMessage(connectionName_, MessageType::TOKEN_AUTH,
        [&connSpecificInvoked](const Attributes &, OnMessageReply &) { connSpecificInvoked = true; });

    Attributes msg;
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, 1);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::TOKEN_AUTH));

    channel_->TriggerRawMessage(connectionName_, msg.Serialize());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(connSpecificInvoked);
    EXPECT_FALSE(incomingInvoked);
}

HWTEST_F(MessageRouterTest, HandleReply_001, TestSize.Level0)
{
    Attributes request;

    bool sendResult = router_->SendMessage(connectionName_, MessageType::KEEP_ALIVE, request, nullptr);
    ASSERT_TRUE(sendResult);

    Attributes sentMessage(channel_->GetSentMessages().back());
    uint32_t messageSeq = 0;
    ASSERT_TRUE(sentMessage.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, messageSeq));

    Attributes reply;
    reply.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    reply.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, messageSeq);
    reply.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, true);
    reply.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(MessageType::KEEP_ALIVE));

    channel_->TriggerRawMessage(connectionName_, reply.Serialize());
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(MessageRouterTest, HandleConnectionDown_001, TestSize.Level0)
{
    bool replyReceived = false;
    Attributes request;

    bool sendResult = router_->SendMessage(connectionName_, MessageType::KEEP_ALIVE, request,
        [&replyReceived](const Attributes &) { replyReceived = true; });
    ASSERT_TRUE(sendResult);

    bool messageReceived = false;
    auto subscription = router_->SubscribeMessage(connectionName_, MessageType::TOKEN_AUTH,
        [&messageReceived](const Attributes &, OnMessageReply &) { messageReceived = true; });
    EXPECT_NE(subscription, nullptr);

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 1);
    EXPECT_EQ(router_->subscriptions_.size(), 1);

    router_->HandleConnectionDown(connectionName_);

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 0);
    EXPECT_EQ(router_->subscriptions_.size(), 1); // Subscription is not cleared by HandleConnectionDown
    EXPECT_EQ(router_->connectionStatusSubscriptions_.count(connectionName_), 0);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(replyReceived);
}

HWTEST_F(MessageRouterTest, HandleConnectionDown_002, TestSize.Level0)
{
    std::string otherConnectionName = "other-connection";
    PhysicalDeviceKey physicalDeviceKey;
    physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    physicalDeviceKey.deviceId = "other-remote-device";
    ASSERT_TRUE(connectionManager_->HandleIncomingConnection(otherConnectionName, physicalDeviceKey));

    Attributes request;
    bool reply1Received = false;
    bool reply2Received = false;

    ASSERT_TRUE(router_->SendMessage(connectionName_, MessageType::KEEP_ALIVE, request,
        [&reply1Received](const Attributes &) { reply1Received = true; }));

    ASSERT_TRUE(router_->SendMessage(otherConnectionName, MessageType::KEEP_ALIVE, request,
        [&reply2Received](const Attributes &) { reply2Received = true; }));

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 2);

    router_->HandleConnectionDown(connectionName_);

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 1);

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(MessageRouterTest, HandleConnectionDown_003, TestSize.Level0)
{
    router_->HandleConnectionDown("non-existent-connection");

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 0);
}

HWTEST_F(MessageRouterTest, HandleConnectionDown_004, TestSize.Level0)
{
    bool messageReceived = false;
    auto subscription = router_->SubscribeMessage(connectionName_, MessageType::TOKEN_AUTH,
        [&messageReceived](const Attributes &, OnMessageReply &) { messageReceived = true; });

    bool incomingReceived = false;
    auto incomingSubscription = router_->SubscribeIncomingConnection(MessageType::TOKEN_AUTH,
        [&incomingReceived](const Attributes &, OnMessageReply &) { incomingReceived = true; });

    EXPECT_EQ(router_->subscriptions_.size(), 2);

    router_->HandleConnectionDown(connectionName_);

    EXPECT_EQ(router_->subscriptions_.size(), 2); // Subscriptions are not cleared by HandleConnectionDown
}

HWTEST_F(MessageRouterTest, HandleMessageTimeout_001, TestSize.Level0)
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

    Attributes sentMessage(channel_->GetSentMessages().back());
    uint32_t messageSeq = 0;
    ASSERT_TRUE(sentMessage.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, messageSeq));

    router_->HandleMessageTimeout(messageSeq);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(replyReceived);
    EXPECT_EQ(replyCode, TIMEOUT);

    EXPECT_EQ(router_->pendingReplyMessages_.count(messageSeq), 0);
}

HWTEST_F(MessageRouterTest, HandleMessageTimeout_002, TestSize.Level0)
{
    uint32_t nonExistentSeq = UINT32_TEST_INVALID_MESSAGE_SEQ;

    ASSERT_NE(router_, nullptr);

    router_->HandleMessageTimeout(nonExistentSeq);
}

HWTEST_F(MessageRouterTest, HandleMessageTimeout_003, TestSize.Level0)
{
    Attributes request;

    bool sendResult = router_->SendMessage(connectionName_, MessageType::KEEP_ALIVE, request, nullptr);
    ASSERT_TRUE(sendResult);

    Attributes sentMessage(channel_->GetSentMessages().back());
    uint32_t messageSeq = 0;
    ASSERT_TRUE(sentMessage.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, messageSeq));

    router_->HandleMessageTimeout(messageSeq);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(router_->pendingReplyMessages_.count(messageSeq), 0);
}

HWTEST_F(MessageRouterTest, HandleTimeoutCheck_001, TestSize.Level0)
{
    Attributes request;

    bool sendResult = router_->SendMessage(connectionName_, MessageType::KEEP_ALIVE, request, nullptr);
    ASSERT_TRUE(sendResult);

    size_t initialSize = router_->pendingReplyMessages_.size();
    EXPECT_EQ(initialSize, 1);

    router_->HandleTimeoutCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(router_->pendingReplyMessages_.size(), initialSize);
}

HWTEST_F(MessageRouterTest, HandleTimeoutCheck_002, TestSize.Level0)
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

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 1);

    auto &pendingMsg = router_->pendingReplyMessages_.begin()->second;

    // Advance time to ensure sendTimeMs is in the past
    timeKeeper_->AdvanceSteadyTime(INT32_TEST_TIMEOUT_OFFSET_MS);

    auto currentTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    ASSERT_TRUE(currentTimeMs.has_value());
    pendingMsg.sendTimeMs = currentTimeMs.value() - INT32_TEST_TIMEOUT_OFFSET_MS;

    router_->HandleTimeoutCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(replyReceived);
    EXPECT_EQ(replyCode, TIMEOUT);

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 0);
}

HWTEST_F(MessageRouterTest, HandleTimeoutCheck_003, TestSize.Level0)
{
    std::string otherConnectionName = "other-connection";
    PhysicalDeviceKey physicalDeviceKey;
    physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    physicalDeviceKey.deviceId = "other-remote-device";
    ASSERT_TRUE(connectionManager_->HandleIncomingConnection(otherConnectionName, physicalDeviceKey));

    Attributes request;
    bool reply1Received = false;
    bool reply2Received = false;
    int32_t replyCode1 = -1;
    int32_t replyCode2 = -1;

    ASSERT_TRUE(router_->SendMessage(connectionName_, MessageType::KEEP_ALIVE, request,
        [&reply1Received, &replyCode1](const Attributes &reply) {
            reply1Received = true;
            (void)reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyCode1);
        }));

    ASSERT_TRUE(router_->SendMessage(otherConnectionName, MessageType::KEEP_ALIVE, request,
        [&reply2Received, &replyCode2](const Attributes &reply) {
            reply2Received = true;
            (void)reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyCode2);
        }));

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 2);

    auto it = router_->pendingReplyMessages_.begin();
    auto currentTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    ASSERT_TRUE(currentTimeMs.has_value());
    it->second.sendTimeMs = currentTimeMs.value() - INT32_TEST_TIMEOUT_OFFSET_MS;

    router_->HandleTimeoutCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(reply1Received);
    EXPECT_EQ(replyCode1, TIMEOUT);

    EXPECT_FALSE(reply2Received);

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 1);
}

HWTEST_F(MessageRouterTest, HandleTimeoutCheck_004, TestSize.Level0)
{
    EXPECT_EQ(router_->pendingReplyMessages_.size(), 0);

    router_->HandleTimeoutCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(router_->pendingReplyMessages_.size(), 0);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
