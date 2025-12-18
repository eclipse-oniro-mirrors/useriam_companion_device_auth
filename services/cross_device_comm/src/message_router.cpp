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

#include "message_router.h"

#include <cinttypes>
#include <utility>

#include "common_defines.h"
#include "iam_check.h"
#include "iam_logger.h"

#include "relative_timer.h"
#include "scope_guard.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

bool MessageRouter::SubscriptionKey::operator<(const SubscriptionKey &other) const
{
    if (connectionName != other.connectionName) {
        return connectionName < other.connectionName;
    }

    return msgType < other.msgType;
}

std::shared_ptr<MessageRouter> MessageRouter::Create(std::shared_ptr<ConnectionManager> connectionMgr,
    std::shared_ptr<ChannelManager> channelMgr)
{
    auto router = std::shared_ptr<MessageRouter>(new (std::nothrow) MessageRouter(connectionMgr, channelMgr));
    ENSURE_OR_RETURN_VAL(router != nullptr, nullptr);

    if (!router->Initialize()) {
        IAM_LOGE("failed to initialize MessageRouter");
        return nullptr;
    }

    return router;
}

MessageRouter::MessageRouter(std::shared_ptr<ConnectionManager> connectionMgr,
    std::shared_ptr<ChannelManager> channelMgr)
    : connectionMgr_(connectionMgr),
      channelMgr_(channelMgr)
{
}

bool MessageRouter::Initialize()
{
    ENSURE_OR_RETURN_VAL(connectionMgr_ != nullptr, false);
    ENSURE_OR_RETURN_VAL(channelMgr_ != nullptr, false);

    auto weakSelf = weak_from_this();
    for (const auto &channel : channelMgr_->GetAllChannels()) {
        ChannelId channelId = channel->GetChannelId();
        auto subscription = channel->SubscribeRawMessage(
            [weakSelf](const std::string &connectionName, const std::vector<uint8_t> &rawMsg) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleRawMessage(connectionName, rawMsg);
            });
        if (subscription != nullptr) {
            channelSubscriptions_[channelId] = std::move(subscription);
        }
    }

    IAM_LOGI("initialized");
    return true;
}

std::unique_ptr<Subscription> MessageRouter::SubscribeIncomingConnection(MessageType msgType, OnMessage &&onMessage)
{
    SubscriptionKey key;
    key.connectionName = "";
    key.msgType = msgType;

    RegisterSubscription(key, std::move(onMessage),
        "incoming connection subscription added: type=" + std::to_string(static_cast<uint32_t>(msgType)));

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, key]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnregisterSubscription(key);
    });
}

std::unique_ptr<Subscription> MessageRouter::SubscribeMessage(const std::string &connectionName, MessageType msgType,
    OnMessage &&onMessage)
{
    SubscriptionKey key;
    key.connectionName = connectionName;
    key.msgType = msgType;

    RegisterSubscription(key, std::move(onMessage),
        "message subscription added: conn=" + connectionName +
            ", type=" + std::to_string(static_cast<uint32_t>(msgType)));

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, key]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnregisterSubscription(key);
    });
}

void MessageRouter::RegisterSubscription(const SubscriptionKey &key, OnMessage &&onMessage, const std::string &logMsg)
{
    if (subscriptions_.find(key) != subscriptions_.end()) {
        IAM_LOGE("subscription already exists, will be overwritten: %{public}s", logMsg.c_str());
    }
    subscriptions_[key] = std::move(onMessage);
    IAM_LOGI("%{public}s success", logMsg.c_str());
}

void MessageRouter::UnregisterSubscription(const SubscriptionKey &key)
{
    subscriptions_.erase(key);
    IAM_LOGI("subscription removed");
}

OnMessage MessageRouter::FindMessageSubscriber(const std::string &connectionName, MessageType msgType)
{
    if (!connectionName.empty()) {
        SubscriptionKey connectionKey;
        connectionKey.connectionName = connectionName;
        connectionKey.msgType = msgType;

        auto it = subscriptions_.find(connectionKey);
        if (it != subscriptions_.end()) {
            return it->second;
        }
    }

    SubscriptionKey incomingConnectionKey;
    incomingConnectionKey.connectionName = "";
    incomingConnectionKey.msgType = msgType;

    auto it = subscriptions_.find(incomingConnectionKey);
    if (it != subscriptions_.end()) {
        return it->second;
    }

    return nullptr;
}

bool MessageRouter::SendMessage(const std::string &connectionName, MessageType msgType, Attributes &request,
    OnMessageReply &&onMessageReply)
{
    uint32_t messageSeq = static_cast<uint32_t>(GetMiscManager().GetNextGlobalId());

    IAM_LOGI("sending message: seq=%{public}u, conn=%{public}s, type=%{public}u", messageSeq, connectionName.c_str(),
        static_cast<uint32_t>(msgType));

    MessageHeader header;
    header.connectionName = connectionName;
    header.messageSeq = messageSeq;
    header.isReply = false;
    header.msgType = msgType;
    std::vector<uint8_t> rawMsg = EncodeMessage(header, request);

    ENSURE_OR_RETURN_VAL(connectionMgr_ != nullptr, false);
    auto connection = connectionMgr_->GetConnection(connectionName);
    if (!connection.has_value()) {
        IAM_LOGE("connection not found: %{public}s", connectionName.c_str());
        return false;
    }

    auto channel = channelMgr_->GetChannelById(connection->channelId);
    ENSURE_OR_RETURN_VAL(channel != nullptr, false);

    bool success = channel->SendMessage(connectionName, rawMsg);
    if (!success) {
        IAM_LOGE("send failed, connection down");
        connectionMgr_->CloseConnection(connectionName, "send_failed");
        return false;
    }

    PendingReplyMessage pending;
    pending.connectionName = connectionName;
    pending.messageSeq = messageSeq;
    pending.msgType = msgType;
    pending.replyCallback = std::move(onMessageReply);
    pending.sendTime = std::chrono::steady_clock::now();

    pendingReplyMessages_[messageSeq] = std::move(pending);

    RefreshConnectionStatusSubscription(connectionName);
    RefreshTimeOutSubscription();

    IAM_LOGI("message sent successfully: seq=%{public}u", messageSeq);
    return true;
}

void MessageRouter::HandleRawMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg)
{
    IAM_LOGI("received message: conn=%{public}s, size=%{public}zu", connectionName.c_str(), rawMsg.size());

    MessageHeader header;
    Attributes payload;
    if (!DecodeMessage(rawMsg, header, payload)) {
        IAM_LOGE("failed to decode message");
        return;
    }

    ENSURE_OR_RETURN(connectionMgr_ != nullptr);
    auto connection = connectionMgr_->GetConnection(header.connectionName);
    if (!connection.has_value()) {
        IAM_LOGE("connection not found: %{public}s", header.connectionName.c_str());
        return;
    }
    ChannelId channelId = connection->channelId;

    Attributes updatedPayload = payload;
    updatedPayload.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, connection->remotePhysicalDeviceKey.deviceId);
    updatedPayload.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(connection->remotePhysicalDeviceKey.idType));

    if (header.isReply) {
        HandleReply(header, updatedPayload);
        return;
    }

    HandleRequest(header, updatedPayload, channelId);
}

void MessageRouter::HandleReply(const MessageHeader &header, const Attributes &payload)
{
    IAM_LOGI("handling reply: seq=%{public}u", header.messageSeq);

    auto it = pendingReplyMessages_.find(header.messageSeq);
    if (it == pendingReplyMessages_.end()) {
        IAM_LOGW("no pending reply message found for seq: %{public}u", header.messageSeq);
        return;
    }

    auto pending = std::move(it->second);
    pendingReplyMessages_.erase(it);

    RefreshConnectionStatusSubscription(pending.connectionName);
    RefreshTimeOutSubscription();

    ENSURE_OR_RETURN(pending.replyCallback != nullptr);
    TaskRunnerManager::GetInstance().PostTaskOnResident([cb = std::move(pending.replyCallback), payload]() {
        if (cb) {
            cb(payload);
        }
    });
    IAM_LOGI("reply handled: seq=%{public}u", header.messageSeq);
}

void MessageRouter::HandleRequest(const MessageHeader &header, const Attributes &payload, ChannelId channelId)
{
    IAM_LOGI("handling request: seq=%{public}u, conn=%{public}s, type=%{public}u", header.messageSeq,
        header.connectionName.c_str(), static_cast<uint32_t>(header.msgType));

    ScopeGuard scopeGuard([weakSelf = weak_from_this(), header, channelId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->SendErrorReply(header, channelId);
    });

    OnMessage callback = FindMessageSubscriber(header.connectionName, header.msgType);
    ENSURE_OR_RETURN(callback != nullptr);

    OnMessageReply replyCallback = [weakSelf = weak_from_this(), requestHeader = header, channelId](
                                       const Attributes &reply) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->SendReply(requestHeader, channelId, reply);
    };

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [cb = callback, data = std::move(payload), reply = std::move(replyCallback)]() mutable {
            if (cb) {
                cb(data, reply);
            }
        });
    scopeGuard.Cancel();
}

void MessageRouter::SendErrorReply(const MessageHeader &requestHeader, ChannelId channelId)
{
    auto channel = channelMgr_->GetChannelById(channelId);
    ENSURE_OR_RETURN(channel != nullptr);

    MessageHeader replyHeader = requestHeader;
    replyHeader.isReply = true;

    Attributes errorReply;
    errorReply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, GENERAL_ERROR);

    channel->SendMessage(replyHeader.connectionName, EncodeMessage(replyHeader, errorReply));
    IAM_LOGI("error reply sent");
}

void MessageRouter::SendReply(const MessageHeader &requestHeader, ChannelId channelId, const Attributes &reply)
{
    MessageHeader replyHeader = requestHeader;
    replyHeader.isReply = true;
    std::vector<uint8_t> rawMsg = EncodeMessage(replyHeader, reply);

    auto channel = channelMgr_->GetChannelById(channelId);
    ENSURE_OR_RETURN(channel != nullptr);

    channel->SendMessage(requestHeader.connectionName, rawMsg);
    IAM_LOGI("reply sent: seq=%{public}u, type=%{public}u", requestHeader.messageSeq,
        static_cast<uint32_t>(requestHeader.msgType));
}

void MessageRouter::HandleConnectionDown(const std::string &connectionName)
{
    IAM_LOGI("connection down: %{public}s", connectionName.c_str());

    for (auto it = pendingReplyMessages_.begin(); it != pendingReplyMessages_.end();) {
        if (it->second.connectionName == connectionName) {
            it = pendingReplyMessages_.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = subscriptions_.begin(); it != subscriptions_.end();) {
        if (!it->first.connectionName.empty() && it->first.connectionName == connectionName) {
            it = subscriptions_.erase(it);
        } else {
            ++it;
        }
    }

    connectionStatusSubscriptions_.erase(connectionName);

    RefreshTimeOutSubscription();

    IAM_LOGI("cleanup completed for connection: %{public}s", connectionName.c_str());
}

void MessageRouter::HandleMessageTimeout(uint32_t messageSeq)
{
    IAM_LOGE("message timeout: seq=%{public}u", messageSeq);

    auto it = pendingReplyMessages_.find(messageSeq);
    if (it == pendingReplyMessages_.end()) {
        return;
    }

    std::string connectionName = it->second.connectionName;

    auto pending = std::move(it->second);
    Attributes errorReply;
    errorReply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, TIMEOUT);

    pendingReplyMessages_.erase(it);

    RefreshConnectionStatusSubscription(connectionName);
    RefreshTimeOutSubscription();

    if (pending.replyCallback) {
        TaskRunnerManager::GetInstance().PostTaskOnResident(
            [cb = std::move(pending.replyCallback), reply = std::move(errorReply)]() {
                if (cb) {
                    cb(reply);
                }
            });
    }
    ENSURE_OR_RETURN(connectionMgr_ != nullptr);
    connectionMgr_->CloseConnection(connectionName, "message_timeout");
}

void MessageRouter::RefreshConnectionStatusSubscription(const std::string &connectionName)
{
    bool hasPendingMessages = false;
    for (const auto &pair : pendingReplyMessages_) {
        if (pair.second.connectionName == connectionName) {
            hasPendingMessages = true;
            break;
        }
    }

    if (hasPendingMessages) {
        if (connectionStatusSubscriptions_.find(connectionName) != connectionStatusSubscriptions_.end()) {
            return;
        }

        ENSURE_OR_RETURN(connectionMgr_ != nullptr);
        auto weakSelf = weak_from_this();
        auto subscription = connectionMgr_->SubscribeConnectionStatus(connectionName,
            [weakSelf](const std::string &connName, ConnectionStatus status, const std::string &reason) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                if (status == ConnectionStatus::DISCONNECTED) {
                    self->HandleConnectionDown(connName);
                }
            });
        ENSURE_OR_RETURN(subscription != nullptr);
        connectionStatusSubscriptions_[connectionName] = std::move(subscription);
        IAM_LOGI("connection status subscription added: %{public}s", connectionName.c_str());
    } else {
        if (connectionStatusSubscriptions_.erase(connectionName) > 0) {
            IAM_LOGI("connection status subscription removed: %{public}s", connectionName.c_str());
        }
    }
}

void MessageRouter::RefreshTimeOutSubscription()
{
    bool hasPendingMessages = !pendingReplyMessages_.empty();
    if (hasPendingMessages) {
        if (timeoutCheckTimerSubscription_ != nullptr) {
            return;
        }

        auto weakSelf = weak_from_this();
        timeoutCheckTimerSubscription_ = RelativeTimer::GetInstance().RegisterPeriodic(
            [weakSelf]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleTimeoutCheck();
            },
            TIMEOUT_CHECK_INTERVAL_MS);
        ENSURE_OR_RETURN(timeoutCheckTimerSubscription_ != nullptr);
        IAM_LOGI("timeout check started");
    } else {
        if (timeoutCheckTimerSubscription_ != nullptr) {
            timeoutCheckTimerSubscription_.reset();
            IAM_LOGI("timeout check stopped");
        }
    }
}

void MessageRouter::HandleTimeoutCheck()
{
    auto now = std::chrono::steady_clock::now();
    std::chrono::milliseconds timeoutDuration(MESSAGE_TIMEOUT_MS);

    std::vector<uint32_t> timeoutMessages;

    for (const auto &pair : pendingReplyMessages_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - pair.second.sendTime);
        if (elapsed >= timeoutDuration) {
            timeoutMessages.push_back(pair.first);
        }
    }

    for (uint32_t messageSeq : timeoutMessages) {
        HandleMessageTimeout(messageSeq);
    }
}

bool MessageRouter::DecodeMessage(const std::vector<uint8_t> &rawMsg, MessageHeader &header, Attributes &payload)
{
    Attributes attributes(rawMsg);

    bool getConnectionNameRet =
        attributes.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, header.connectionName);
    ENSURE_OR_RETURN_VAL(getConnectionNameRet, false);

    bool getMessageSeqRet = attributes.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, header.messageSeq);
    ENSURE_OR_RETURN_VAL(getMessageSeqRet, false);

    bool getIsReplyRet = attributes.GetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, header.isReply);
    ENSURE_OR_RETURN_VAL(getIsReplyRet, false);

    uint32_t msgTypeValue = 0;
    bool getMsgTypeRet = attributes.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_TYPE, msgTypeValue);
    ENSURE_OR_RETURN_VAL(getMsgTypeRet, false);
    header.msgType = static_cast<MessageType>(msgTypeValue);

    payload = std::move(attributes);
    return true;
}

std::vector<uint8_t> MessageRouter::EncodeMessage(const MessageHeader &header, const Attributes &payload)
{
    Attributes message(payload.Serialize());
    message.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, header.connectionName);
    message.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, static_cast<uint32_t>(header.messageSeq));
    message.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, header.isReply);
    message.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint32_t>(header.msgType));

    return message.Serialize();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
