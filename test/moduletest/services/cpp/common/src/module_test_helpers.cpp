/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "module_test_helpers.h"

#include "binding_signature_message.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::optional<RawMsgInfo> DecodeRawMsg(const std::vector<uint8_t> &rawMsg)
{
    Attributes attr(rawMsg);
    RawMsgInfo info;
    if (!attr.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, info.connectionName)) {
        return std::nullopt;
    }
    if (!attr.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, info.seq)) {
        return std::nullopt;
    }
    if (!attr.GetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, info.isReply)) {
        return std::nullopt;
    }
    uint16_t msgType = 0;
    if (!attr.GetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, msgType)) {
        return std::nullopt;
    }
    info.msgType = static_cast<MessageType>(msgType);
    info.payload = attr;
    return info;
}

std::optional<RawMsgInfo> CaptureAndReply(FakeChannel &channel, const std::string &connName,
    MessageType expectedMsgType, const Attributes &replyPayload)
{
    auto sentMsgs = channel.GetSentMessages(connName);
    if (sentMsgs.empty()) {
        return std::nullopt;
    }
    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    if (!msgInfo.has_value()) {
        return std::nullopt;
    }
    auto replyRawMsg = BuildReplyRawMsg(connName, msgInfo->seq, expectedMsgType, replyPayload);
    channel.ClearSentMessages();
    channel.TestSimulateIncomingMessage(connName, replyRawMsg);
    DrainPendingTasks();
    return msgInfo;
}

bool InjectBindingSignatureChallengeReply(FakeChannel &channel, const DeviceKey &companionDeviceKey)
{
    auto allConnNames = channel.GetAllConnectionNames();
    for (const auto &connName : allConnNames) {
        auto sentMsgs = channel.GetSentMessages(connName);
        for (const auto &rawMsg : sentMsgs) {
            Attributes attr(rawMsg);
            uint16_t msgType = 0;
            if (!attr.GetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, msgType)) {
                continue;
            }
            if (static_cast<MessageType>(msgType) != MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                continue;
            }
            uint32_t seq = 0;
            attr.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, seq);

            GetBindingSignatureChallengeReply challengeReply;
            challengeReply.result = ResultCode::SUCCESS;
            challengeReply.companionUserKey =
                UserKey { companionDeviceKey.deviceUserId, companionDeviceKey.deviceSubProfileId };
            challengeReply.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0x01);

            Attributes replyPayload;
            EncodeGetBindingSignatureChallengeReply(challengeReply, replyPayload);
            replyPayload.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
                static_cast<int32_t>(companionDeviceKey.idType));
            replyPayload.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionDeviceKey.deviceId);

            Attributes replyMsg(replyPayload.Serialize());
            replyMsg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connName);
            replyMsg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, seq);
            replyMsg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, true);
            replyMsg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE,
                static_cast<uint16_t>(MessageType::GET_BINDING_SIGNATURE_CHALLENGE));

            channel.ClearSentMessages();
            channel.TestSimulateIncomingMessage(connName, replyMsg.Serialize());
            return true;
        }
    }
    return false;
}

bool InjectSyncDeviceStatusReply(FakeChannel &channel, const SyncDeviceStatusReply &syncReply,
    const DeviceKey &companionDeviceKey)
{
    // A sync round over a device with any valid binding starts with the challenge probe:
    // answer it (host downgrades to an unprotected V1 sync) so the SYNC message that the
    // scan below expects actually reaches the wire.
    if (InjectBindingSignatureChallengeReply(channel, companionDeviceKey)) {
        DrainPendingTasks();
    }

    auto allConnNames = channel.GetAllConnectionNames();
    for (const auto &connName : allConnNames) {
        auto sentMsgs = channel.GetSentMessages(connName);
        for (const auto &rawMsg : sentMsgs) {
            Attributes attr(rawMsg);
            uint16_t msgType = 0;
            if (!attr.GetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, msgType)) {
                continue;
            }
            if (static_cast<MessageType>(msgType) != MessageType::SYNC_DEVICE_STATUS) {
                continue;
            }
            uint32_t seq = 0;
            attr.GetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, seq);

            Attributes replyPayload;
            EncodeSyncDeviceStatusReply(syncReply, replyPayload);
            replyPayload.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
                static_cast<int32_t>(companionDeviceKey.idType));
            replyPayload.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionDeviceKey.deviceId);

            Attributes replyMsg(replyPayload.Serialize());
            replyMsg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connName);
            replyMsg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, seq);
            replyMsg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, true);
            replyMsg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE,
                static_cast<uint16_t>(MessageType::SYNC_DEVICE_STATUS));

            channel.ClearSentMessages();
            channel.TestSimulateIncomingMessage(connName, replyMsg.Serialize());
            return true;
        }
    }
    return false;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
