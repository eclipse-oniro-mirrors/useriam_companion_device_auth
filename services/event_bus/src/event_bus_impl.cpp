/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "event_bus_impl.h"

#include <new>

#include "iam_check.h"
#include "iam_logger.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_EVENT_BUS_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

EventBusImpl::EventBusImpl()
{
}

std::shared_ptr<EventBusImpl> EventBusImpl::Create()
{
    IAM_LOGI("start");
    auto eventBus = std::shared_ptr<EventBusImpl>(new (std::nothrow) EventBusImpl());
    ENSURE_OR_RETURN_VAL(eventBus != nullptr, nullptr);
    return eventBus;
}

void EventBusImpl::Publish(EventType type, const EventData &data)
{
    IAM_LOGI("publish event type=%{public}hu data size=%{public}zu", type, data.size());
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), type, data]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);

        auto it = self->subscribers_.find(type);
        if (it == self->subscribers_.end()) {
            IAM_LOGI("no subscribers for event type=%{public}hu", type);
            return;
        }

        for (const auto &subscriber : it->second) {
            if (subscriber.second) {
                subscriber.second(data);
            }
        }
    });
}

std::shared_ptr<Subscription> EventBusImpl::Subscribe(EventType type, EventDataHandler &&handler)
{
    IAM_LOGI("subscribe event type=%{public}hu", type);
    ENSURE_OR_RETURN_VAL(handler != nullptr, nullptr);

    SubscribeId id = ++nextSubscribeId_;
    subscribers_[type][id] = std::move(handler);

    auto weakSelf = weak_from_this();
    return std::make_shared<Subscription>([weakSelf, type, id]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->Unsubscribe(type, id);
    });
}

void EventBusImpl::PersistSubscribe(EventType type, EventDataHandler &&handler)
{
    IAM_LOGI("subscribe event type=%{public}hu", type);
    ENSURE_OR_RETURN(handler != nullptr);

    SubscribeId id = ++nextSubscribeId_;
    subscribers_[type][id] = std::move(handler);
}

void EventBusImpl::Unsubscribe(EventType type, SubscribeId id)
{
    auto it = subscribers_.find(type);
    if (it == subscribers_.end()) {
        return;
    }

    it->second.erase(id);
    if (it->second.empty()) {
        subscribers_.erase(it);
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
