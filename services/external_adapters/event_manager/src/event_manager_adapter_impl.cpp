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

#include "event_manager_adapter_impl.h"

#include "adapter_manager.h"
#include "hisysevent.h"
#include "iam_logger.h"
#include "interaction_event_collector.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_EVENT_MANAGER_ADAPTER_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;

constexpr char STR_REQUEST_TYPE[] = "REQUEST_TYPE";
constexpr char STR_RESULT[] = "RESULT";
constexpr char STR_HOST_USER_ID[] = "HOST_USER_ID";
constexpr char STR_HOST_DEVICE_KEY[] = "HOST_DEVICE_KEY";
constexpr char STR_COMPANION_USER_ID[] = "COMPANION_USER_ID";
constexpr char STR_COMPANION_DEVICE_KEY[] = "COMPANION_DEVICE_KEY";
constexpr char STR_CONNECTION_NAME[] = "CONNECTION_NAME";
constexpr char STR_SCHEDULE_ID[] = "SCHEDULE_ID";
constexpr char STR_TRIGGER_REASON[] = "TRIGGER_REASON";
constexpr char STR_TEMPLATE_ID_LIST[] = "TEMPLATE_ID_LIST";
constexpr char STR_EXTRA_INFO[] = "EXTRA_INFO";
constexpr char STR_FAULT_TYPE[] = "FAULT_TYPE";
constexpr char STR_FAULT_ID[] = "FAULT_ID";
constexpr char STR_FAULT_INFO[] = "FAULT_INFO";

void EventManagerAdapterImpl::ReportSystemFault(std::string faultType, std::string faultId, std::string faultInfo)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::COMPANION_AUTH, "SYSTEM_FAULT", HiSysEvent::EventType::FAULT,
        STR_FAULT_TYPE, faultType, STR_FAULT_ID, faultId, STR_FAULT_INFO, faultInfo);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void EventManagerAdapterImpl::ReportInteractionEvent(const InteractionEventCollector &eventCollector)
{
    std::string resultStr = std::to_string(static_cast<int32_t>(eventCollector.GetResult()));
    int32_t hostUserId = eventCollector.GetHostUserId().value_or(0);
    std::string hostDeviceKey =
        eventCollector.GetHostDeviceKey().has_value() ? eventCollector.GetHostDeviceKey()->GetDesc() : "";
    int32_t companionUserId = eventCollector.GetCompanionUserId().value_or(0);
    std::string companionDeviceKey =
        eventCollector.GetCompanionDeviceKey().has_value() ? eventCollector.GetCompanionDeviceKey()->GetDesc() : "";
    std::string connectionName = eventCollector.GetConnectionName().value_or("");
    uint64_t scheduleId = eventCollector.GetScheduleId().value_or(0);
    std::string triggerReason = eventCollector.GetTriggerReason().value_or("");

    std::string templateIdList;
    if (eventCollector.GetTemplateIdList().has_value() && !eventCollector.GetTemplateIdList()->empty()) {
        templateIdList = GetMaskedVectorString(*eventCollector.GetTemplateIdList());
    }

    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::COMPANION_AUTH, "INTERACTION_EVENT", HiSysEvent::EventType::FAULT,
        STR_REQUEST_TYPE, eventCollector.GetRequestType(), STR_RESULT, resultStr, STR_HOST_USER_ID, hostUserId,
        STR_HOST_DEVICE_KEY, hostDeviceKey, STR_COMPANION_USER_ID, companionUserId, STR_COMPANION_DEVICE_KEY,
        companionDeviceKey, STR_CONNECTION_NAME, connectionName, STR_SCHEDULE_ID, scheduleId, STR_TRIGGER_REASON,
        triggerReason, STR_TEMPLATE_ID_LIST, templateIdList, STR_EXTRA_INFO, eventCollector.GetExtraInfo());
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void ReportSystemFault(std::string faultType, std::string faultId, std::string faultInfo)
{
    GetEventManagerAdapter().ReportSystemFault(faultType, faultId, faultInfo);
}

void ReportInteractionEvent(const InteractionEventCollector &eventCollector)
{
    GetEventManagerAdapter().ReportInteractionEvent(eventCollector);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
