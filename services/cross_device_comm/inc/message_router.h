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

#ifndef COMPANION_DEVICE_AUTH_MESSAGE_ROUTER_H
#define COMPANION_DEVICE_AUTH_MESSAGE_ROUTER_H

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "cda_attributes.h"
#include "connection_manager.h"
#include "cross_device_common.h"
#include "icross_device_channel.h"
#include "misc_manager.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MessageRouter : public NoCopyable, public std::enable_shared_from_this<MessageRouter> {
public:
    static std::shared_ptr<MessageRouter> Create(std::shared_ptr<ConnectionManager> connectionMgr,
        std::shared_ptr<ChannelManager> channelMgr);

    ~MessageRouter() = default;

    std::unique_ptr<Subscription> SubscribeIncomingConnection(MessageType msgType, OnMessage &&onMessage);
    std::unique_ptr<Subscription> SubscribeMessage(const std::string &connectionName, MessageType msgType,
        OnMessage &&onMessage);

    bool SendMessage(const std::string &connectionName, MessageType msgType, Attributes &request,
        OnMessageReply &&onMessageReply);

    void HandleRawMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg);
    void HandleConnectionDown(const std::string &connectionName);

#ifndef ENABLE_TEST
private:
#endif
    static constexpr int32_t MESSAGE_TIMEOUT_MS = 5000;
    static constexpr int32_t TIMEOUT_CHECK_INTERVAL_MS = 1000;
    static constexpr size_t MAX_PENDING_MESSAGES = 100;

    bool Initialize();

    struct SubscriptionKey {
        MessageType msgType { MessageType::INVALID };
        std::string connectionName { "" };
        bool operator<(const SubscriptionKey &other) const;
    };

    struct PendingReplyMessage {
        std::string connectionName;
        uint32_t messageSeq;
        MessageType msgType { MessageType::INVALID };
        OnMessageReply replyCallback;
        std::chrono::steady_clock::time_point sendTime;
    };

    struct MessageHeader {
        std::string connectionName;
        uint32_t messageSeq { 0 };
        bool isReply { false };
        MessageType msgType { MessageType::INVALID };
    };

    bool DecodeMessage(const std::vector<uint8_t> &rawMsg, MessageHeader &header, Attributes &payload);
    std::vector<uint8_t> EncodeMessage(const MessageHeader &header, const Attributes &payload);

    void HandleRequest(const MessageHeader &header, const Attributes &payload, ChannelId channelId);
    void HandleReply(const MessageHeader &header, const Attributes &payload);

    void RegisterSubscription(const SubscriptionKey &key, OnMessage &&onMessage, const std::string &logMsg);
    void UnregisterSubscription(const SubscriptionKey &key);

    void RefreshConnectionStatusSubscription(const std::string &connectionName);
    void RefreshTimeOutSubscription();
    void HandleTimeoutCheck();
    void HandleMessageTimeout(uint32_t messageSeq);

    OnMessage FindMessageSubscriber(const std::string &connectionName, MessageType msgType);
    void SendErrorReply(const MessageHeader &requestHeader, ChannelId channelId);
    void SendReply(const MessageHeader &requestHeader, ChannelId channelId, const Attributes &reply);

    std::map<SubscriptionKey, OnMessage> subscriptions_;
    std::map<uint32_t, PendingReplyMessage> pendingReplyMessages_;
    std::map<ChannelId, std::unique_ptr<Subscription>> channelSubscriptions_;
    std::map<std::string, std::unique_ptr<Subscription>> connectionStatusSubscriptions_;
    std::unique_ptr<Subscription> timeoutCheckTimerSubscription_;

    std::shared_ptr<ConnectionManager> connectionMgr_;
    std::shared_ptr<ChannelManager> channelMgr_;

#ifndef ENABLE_TEST
private:
#endif
    MessageRouter(std::shared_ptr<ConnectionManager> connectionMgr, std::shared_ptr<ChannelManager> channelMgr);
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MESSAGE_ROUTER_H
