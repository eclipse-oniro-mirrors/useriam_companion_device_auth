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

#include <iomanip>
#include <sstream>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_safe_arithmetic.h"

#include "adapter_manager.h"
#include "cda_attributes.h"
#include "common_defines.h"
#include "relative_timer.h"
#include "scope_guard.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "time_keeper.h"

#define LOG_TAG "CDA_SA"

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

    for (const auto &channel : channelMgr_->GetAllChannels()) {
        ENSURE_OR_RETURN_VAL(channel != nullptr, false);
        ChannelId channelId = channel->GetChannelId();
        auto subscription = channel->SubscribeRawMessage(
            [weakSelf = weak_from_this()](const std::string &connectionName, const std::vector<uint8_t> &rawMsg) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleRawMessage(connectionName, rawMsg);
            });
        ENSURE_OR_RETURN_VAL(subscription != nullptr, false);
        channelSubscriptions_[channelId] = std::move(subscription);
    }

    IAM_LOGI("initialized");
    return true;
}

std::unique_ptr<Subscription> MessageRouter::SubscribeIncomingConnection(MessageType msgType, OnMessage &&onMessage)
{
    SubscriptionKey key {};
    key.connectionName = "";
    key.msgType = msgType;

    IAM_LOGD("incoming connection subscription added: type=0x%{public}04x", static_cast<uint16_t>(msgType));
    std::ostringstream oss1;
    oss1 << "incoming connection subscription added: type=0x" << std::hex << std::setw(BYTE_NUM_4) << std::setfill('0')
         << static_cast<uint16_t>(msgType);
    RegisterSubscription(key, std::move(onMessage), oss1.str());

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), key]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnregisterSubscription(key);
    });
}

std::unique_ptr<Subscription> MessageRouter::SubscribeMessage(const std::string &connectionName, MessageType msgType,
    OnMessage &&onMessage)
{
    SubscriptionKey key {};
    key.connectionName = connectionName;
    key.msgType = msgType;

    IAM_LOGD("message subscription added: conn=%{public}s, type=0x%{public}04x", connectionName.c_str(),
        static_cast<uint16_t>(msgType));
    std::ostringstream oss2;
    oss2 << "message subscription added: conn=" << connectionName << ", type=0x" << std::hex << std::setw(BYTE_NUM_4)
         << std::setfill('0') << static_cast<uint16_t>(msgType);
    RegisterSubscription(key, std::move(onMessage), oss2.str());

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), key]() {
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
    IAM_LOGD("subscription removed");
}

// connectionName is never empty
OnMessage MessageRouter::FindMessageSubscriber(const std::string &connectionName, MessageType msgType)
{
    if (!connectionName.empty()) {
        SubscriptionKey connectionKey {};
        connectionKey.connectionName = connectionName;
        connectionKey.msgType = msgType;

        auto it = subscriptions_.find(connectionKey);
        if (it != subscriptions_.end()) {
            return it->second;
        }
    }

    SubscriptionKey incomingConnectionKey {};
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
    if (pendingReplyMessages_.size() >= MAX_PENDING_MESSAGES) {
        IAM_LOGE("pending messages limit reached: %{public}zu >= %{public}zu", pendingReplyMessages_.size(),
            MAX_PENDING_MESSAGES);
        return false;
    }

    uint32_t messageSeq = static_cast<uint32_t>(GetMiscManager().GetNextGlobalId());

    IAM_LOGI("sending message: seq=0x%{public}08X, conn=%{public}s, type=0x%{public}04x", messageSeq,
        connectionName.c_str(), static_cast<uint16_t>(msgType));

    MessageHeader header {};
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

    ENSURE_OR_RETURN_VAL(channelMgr_ != nullptr, false);
    auto channel = channelMgr_->GetChannelById(connection->channelId);
    ENSURE_OR_RETURN_VAL(channel != nullptr, false);

    bool success = channel->SendMessage(connectionName, rawMsg);
    if (!success) {
        IAM_LOGE("send failed, connection down");
        if (msgType != MessageType::DISCONNECT) {
            TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), connectionName]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr && self->connectionMgr_ != nullptr);
                self->connectionMgr_->CloseConnection(connectionName, "send_msg_failed");
            });
        }
        return false;
    }

    PendingReplyMessage pending {};
    pending.connectionName = connectionName;
    pending.messageSeq = messageSeq;
    pending.msgType = msgType;
    pending.replyCallback = std::move(onMessageReply);
    auto sendTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN_VAL(sendTimeMs.has_value(), false);
    pending.sendTimeMs = sendTimeMs.value();

    pendingReplyMessages_[messageSeq] = std::move(pending);

    RefreshConnectionStatusSubscription(connectionName);
    RefreshTimeOutSubscription();

    IAM_LOGI("message sent successfully: seq=0x%{public}08X", messageSeq);
    return true;
}

void MessageRouter::HandleRawMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg)
{
    IAM_LOGI("received message: conn=%{public}s, size=%{public}zu", connectionName.c_str(), rawMsg.size());

    if (rawMsg.size() > MAX_MESSAGE_SIZE) {
        IAM_LOGE("message size exceeds limit: %{public}zu > %{public}zu", rawMsg.size(), MAX_MESSAGE_SIZE);
        return;
    }

    MessageHeader header {};
    Attributes payload {};
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
    IAM_LOGI("handling reply: seq=0x%{public}08X", header.messageSeq);

    auto it = pendingReplyMessages_.find(header.messageSeq);
    if (it == pendingReplyMessages_.end()) {
        IAM_LOGW("no pending reply message found for seq: 0x%{public}08X", header.messageSeq);
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
    IAM_LOGI("reply handled: seq=0x%{public}08X", header.messageSeq);
}

void MessageRouter::HandleRequest(const MessageHeader &header, const Attributes &payload, ChannelId channelId)
{
    IAM_LOGI("handling request: seq=0x%{public}08X, conn=%{public}s, type=0x%{public}04x", header.messageSeq,
        header.connectionName.c_str(), static_cast<uint16_t>(header.msgType));

    ENSURE_OR_RETURN(channelMgr_ != nullptr);
    if (header.msgType == MessageType::DISCONNECT) {
        std::string reason;
        if (!payload.GetStringValue(Attributes::ATTR_CDA_SA_REASON, reason)) {
            reason = "unknown";
        }

        IAM_LOGI("received disconnect notification: conn=%{public}s, reason=%{public}s", header.connectionName.c_str(),
            reason.c_str());
        auto channel = channelMgr_->GetChannelById(channelId);
        ENSURE_OR_RETURN(channel != nullptr);
        channel->OnRemoteDisconnect(header.connectionName, reason);
        return;
    }

    ScopeGuard scopeGuard([weakSelf = weak_from_this(), header, channelId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->SendErrorReply(header, channelId);
    });

    OnMessage callback = FindMessageSubscriber(header.connectionName, header.msgType);
    ENSURE_OR_RETURN(callback != nullptr);

    OnMessageReply replyCallback = [weakSelf = weak_from_this(), requestHeader = header, channelId](
                                       const Attributes &reply) {
        TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf, requestHeader, channelId, reply]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->SendReply(requestHeader, channelId, reply);
        });
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
    ENSURE_OR_RETURN(channelMgr_ != nullptr);
    auto channel = channelMgr_->GetChannelById(channelId);
    ENSURE_OR_RETURN(channel != nullptr);

    MessageHeader replyHeader = requestHeader;
    replyHeader.isReply = true;

    Attributes errorReply {};
    errorReply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, GENERAL_ERROR);

    bool sendResult = channel->SendMessage(replyHeader.connectionName, EncodeMessage(replyHeader, errorReply));
    if (!sendResult) {
        IAM_LOGE("failed to send error reply");
        return;
    }
    IAM_LOGI("error reply sent");
}

void MessageRouter::SendReply(const MessageHeader &requestHeader, ChannelId channelId, const Attributes &reply)
{
    MessageHeader replyHeader = requestHeader;
    replyHeader.isReply = true;
    std::vector<uint8_t> rawMsg = EncodeMessage(replyHeader, reply);

    ENSURE_OR_RETURN(channelMgr_ != nullptr);
    auto channel = channelMgr_->GetChannelById(channelId);
    ENSURE_OR_RETURN(channel != nullptr);

    bool sendResult = channel->SendMessage(requestHeader.connectionName, rawMsg);
    if (!sendResult) {
        IAM_LOGE("failed to send reply: seq=0x%{public}08X, type=0x%{public}04x", requestHeader.messageSeq,
            static_cast<uint16_t>(requestHeader.msgType));
        return;
    }
    IAM_LOGI("reply sent: seq=0x%{public}08X, type=0x%{public}04x", requestHeader.messageSeq,
        static_cast<uint16_t>(requestHeader.msgType));
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

    connectionStatusSubscriptions_.erase(connectionName);

    RefreshTimeOutSubscription();

    IAM_LOGI("cleanup completed for connection: %{public}s", connectionName.c_str());
}

void MessageRouter::HandleMessageTimeout(uint32_t messageSeq)
{
    IAM_LOGE("message timeout: seq=0x%{public}08X", messageSeq);

    auto it = pendingReplyMessages_.find(messageSeq);
    if (it == pendingReplyMessages_.end()) {
        return;
    }

    std::string connectionName = it->second.connectionName;

    auto pending = std::move(it->second);
    Attributes errorReply {};
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
        auto subscription = connectionMgr_->SubscribeConnectionStatus(connectionName,
            [weakSelf = weak_from_this()](const std::string &connName, ConnectionStatus status,
                [[maybe_unused]] const std::string &reason) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                if (status == ConnectionStatus::DISCONNECTED) {
                    self->HandleConnectionDown(connName);
                }
            });
        ENSURE_OR_RETURN(subscription != nullptr);
        connectionStatusSubscriptions_[connectionName] = std::move(subscription);
        IAM_LOGD("connection status subscription added: %{public}s", connectionName.c_str());
    } else {
        if (connectionStatusSubscriptions_.erase(connectionName) > 0) {
            IAM_LOGD("connection status subscription removed: %{public}s", connectionName.c_str());
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

        timeoutCheckTimerSubscription_ = RelativeTimer::GetInstance().RegisterPeriodic(
            [weakSelf = weak_from_this()]() {
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
    auto now = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(now.has_value());

    std::vector<uint32_t> timeoutMessages;

    for (const auto &pair : pendingReplyMessages_) {
        auto elapsedMsOpt = safe_sub(now.value(), pair.second.sendTimeMs);
        if (!elapsedMsOpt.has_value()) {
            continue;
        }
        auto elapsedMs = elapsedMsOpt.value();
        if (elapsedMs >= MESSAGE_TIMEOUT_MS) {
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

    uint16_t msgTypeValue = 0;
    bool getMsgTypeRet = attributes.GetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, msgTypeValue);
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
    message.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(header.msgType));

    return message.Serialize();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
