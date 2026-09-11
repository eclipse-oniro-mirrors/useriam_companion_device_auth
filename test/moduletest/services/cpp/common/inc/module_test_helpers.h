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

#ifndef COMPANION_DEVICE_AUTH_MODULE_TEST_HELPERS_H
#define COMPANION_DEVICE_AUTH_MODULE_TEST_HELPERS_H

#include <optional>
#include <string>
#include <vector>

#include "common_message.h"
#include "cross_device_common.h"
#include "fake_channel.h"
#include "relative_timer.h"
#include "sync_device_status_message.h"
#include "task_runner_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Captures FwkResultCallback invocation. Replaces the verbose bool+ResultCode+vector pattern.
struct FwkCallbackCapture {
    bool invoked = false;
    ResultCode result = ResultCode::GENERAL_ERROR;
    std::vector<uint8_t> extraInfo;
    FwkResultCallback MakeCallback()
    {
        return [this](ResultCode r, const std::vector<uint8_t> &ei) {
            invoked = true;
            result = r;
            extraInfo = ei;
        };
    }
};

// Factory helpers for common test data structures

inline PhysicalDeviceKey MakePhysKey(const std::string &deviceId)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = deviceId;
    return key;
}

inline DeviceKey MakeDeviceKey(
    const std::string &deviceId, int32_t userId, int32_t subProfileId = INVALID_SUB_PROFILE_ID)
{
    DeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = deviceId;
    key.deviceUserId = userId;
    key.deviceSubProfileId = subProfileId;
    return key;
}

struct RawMsgInfo {
    std::string connectionName;
    uint32_t seq { 0 };
    bool isReply { false };
    MessageType msgType { MessageType::INVALID };
    Attributes payload;
};

std::optional<RawMsgInfo> DecodeRawMsg(const std::vector<uint8_t> &rawMsg);

inline std::vector<uint8_t> BuildReplyRawMsg(const std::string &connName, uint32_t seq, MessageType msgType,
    const Attributes &replyPayload)
{
    Attributes msg(replyPayload.Serialize());
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connName);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, seq);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, true); // isReply
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(msgType));
    return msg.Serialize();
}

inline std::vector<uint8_t> BuildRequestRawMsg(const std::string &connName, uint32_t seq, MessageType msgType,
    const Attributes &requestPayload)
{
    Attributes msg(requestPayload.Serialize());
    msg.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connName);
    msg.SetUint32Value(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, seq);
    msg.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false); // not reply
    msg.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(msgType));
    return msg.Serialize();
}

// Execute pending TaskRunner tasks only (no timer).
// Use when timer-driven timeouts must not fire yet.
inline void DrainPendingTasks()
{
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
}

// Execute all pending tasks and expired timer callbacks.
// Loops between TaskRunner and RelativeTimer to handle cascading interactions:
// timer callbacks post tasks, and task execution may register new timers.
// Only fires timers whose deadline has been reached (steady time >= deadline).
// Must be called after guard.GetTimeKeeper().AdvanceSteadyTime() to trigger specific timers.
inline void DrainAllTasks()
{
    static constexpr int32_t MAX_DRAIN_ITERATIONS = 20;
    for (int i = 0; i < MAX_DRAIN_ITERATIONS; ++i) {
        TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
        RelativeTimer::GetInstance().DrainExpiredTasks();
    }
}

// Capture the last sent message on a connection, build and inject a reply.
// Returns the captured RawMsgInfo, or nullopt if no message found.
// This extracts the common "capture seq → build reply → inject → drain" pattern
// used in multi-round E2E tests.
std::optional<RawMsgInfo> CaptureAndReply(FakeChannel &channel, const std::string &connName,
    MessageType expectedMsgType, const Attributes &replyPayload);

// Find a SYNC_DEVICE_STATUS request among all connections and inject a reply.
// Used by host-side setup to populate device status (capabilities, device key, user name).
// Returns true if a SYNC_DEVICE_STATUS request was found and replied to.
bool InjectSyncDeviceStatusReply(FakeChannel &channel, const SyncDeviceStatusReply &syncReply,
    const DeviceKey &companionDeviceKey);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MODULE_TEST_HELPERS_H
