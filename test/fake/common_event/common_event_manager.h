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

#ifndef FAKE_COMMON_EVENT_MANAGER_H
#define FAKE_COMMON_EVENT_MANAGER_H

#include <memory>

#include "common_event_subscriber.h"

namespace OHOS {
namespace EventFwk {
// Test seam: the subscriber most recently registered via SubscribeCommonEvent, so a test can fire
// OnReceiveEvent to simulate the system DATA_SHARE_READY broadcast.
inline std::shared_ptr<CommonEventSubscriber> g_lastSubscriber;

class CommonEventManager {
public:
    static bool SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        g_lastSubscriber = subscriber;
        return true;
    }

    static bool UnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &)
    {
        g_lastSubscriber = nullptr;
        return true;
    }
};
} // namespace EventFwk
} // namespace OHOS

#endif // FAKE_COMMON_EVENT_MANAGER_H
