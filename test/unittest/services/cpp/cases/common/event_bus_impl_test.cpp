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

#include <memory>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_guard.h"

#include "event_bus/event_bus.h"
#include "event_bus_impl.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class EventBusImplTest : public Test {};

HWTEST_F(EventBusImplTest, Create_001, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    EXPECT_NE(nullptr, eventBus);
}

HWTEST_F(EventBusImplTest, Publish_001, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
}

HWTEST_F(EventBusImplTest, Publish_002, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callbackCalled = std::make_shared<bool>(false);
    auto subscription = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [callbackCalled](const EventData &data) { *callbackCalled = true; });
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(EventBusImplTest, Publish_003, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callback1Called = std::make_shared<bool>(false);
    auto callback2Called = std::make_shared<bool>(false);
    auto callback3Called = std::make_shared<bool>(false);

    auto subscription1 = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [callback1Called](const EventData &data) { *callback1Called = true; });
    auto subscription2 = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [callback2Called](const EventData &data) { *callback2Called = true; });
    auto subscription = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [callback3Called](const EventData &data) { *callback3Called = true; });

    ASSERT_NE(nullptr, subscription1);
    ASSERT_NE(nullptr, subscription2);
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(*callback1Called);
    EXPECT_TRUE(*callback2Called);
    EXPECT_TRUE(*callback3Called);
}

HWTEST_F(EventBusImplTest, Publish_004, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto receivedData = std::make_shared<std::vector<uint8_t>>();
    auto subscription =
        eventBus->Subscribe(EventType::AUTH_SUCCESS, [receivedData](const EventData &data) { *receivedData = data; });
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> expectedData = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, expectedData);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(expectedData, *receivedData);
}

HWTEST_F(EventBusImplTest, Publish_005, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callbackCalled = std::make_shared<bool>(false);
    auto subscription = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [callbackCalled](const EventData &data) { *callbackCalled = true; });
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(static_cast<EventType>(999), data);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(EventBusImplTest, Publish_006, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callbackCalled = std::make_shared<int>(0);
    auto subscription =
        eventBus->Subscribe(EventType::AUTH_SUCCESS, [callbackCalled](const EventData &data) { (*callbackCalled)++; });
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> data1 = { 0x01, 0x02, 0x03 };
    std::vector<uint8_t> data2 = { 0x04, 0x05, 0x06 };
    std::vector<uint8_t> data3 = { 0x07, 0x08, 0x09 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data1);
    eventBus->Publish(EventType::AUTH_SUCCESS, data2);
    eventBus->Publish(EventType::AUTH_SUCCESS, data3);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(3, *callbackCalled);
}

HWTEST_F(EventBusImplTest, Subscribe_001, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto subscription = eventBus->Subscribe(EventType::AUTH_SUCCESS, [](const EventData &data) {});

    EXPECT_NE(nullptr, subscription);
}

HWTEST_F(EventBusImplTest, Subscribe_002, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto subscription = eventBus->Subscribe(EventType::AUTH_SUCCESS, nullptr);
    EXPECT_EQ(nullptr, subscription);
}

HWTEST_F(EventBusImplTest, Subscribe_003, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto subscription1 = eventBus->Subscribe(EventType::AUTH_SUCCESS, [](const EventData &data) {});
    auto subscription2 = eventBus->Subscribe(EventType::AUTH_SUCCESS, [](const EventData &data) {});

    EXPECT_NE(nullptr, subscription1);
    EXPECT_NE(nullptr, subscription2);
    EXPECT_NE(subscription1, subscription2);
}

HWTEST_F(EventBusImplTest, Unsubscribe_001, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callbackCalled = std::make_shared<int>(0);
    auto subscription =
        eventBus->Subscribe(EventType::AUTH_SUCCESS, [callbackCalled](const EventData &data) { (*callbackCalled)++; });
    ASSERT_NE(nullptr, subscription);

    subscription->Cancel();

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(0, *callbackCalled);
}

HWTEST_F(EventBusImplTest, Unsubscribe_002, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callbackCalled = std::make_shared<int>(0);
    auto subscription =
        eventBus->Subscribe(EventType::AUTH_SUCCESS, [callbackCalled](const EventData &data) { (*callbackCalled)++; });
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(1, *callbackCalled);

    subscription->Cancel();

    eventBus->Publish(EventType::AUTH_SUCCESS, data);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(1, *callbackCalled);
}

HWTEST_F(EventBusImplTest, Unsubscribe_003, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callback1Called = std::make_shared<int>(0);
    auto callback2Called = std::make_shared<int>(0);

    auto subscription1 = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [callback1Called](const EventData &data) { (*callback1Called)++; });
    auto subscription2 = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [callback2Called](const EventData &data) { (*callback2Called)++; });

    ASSERT_NE(nullptr, subscription1);
    ASSERT_NE(nullptr, subscription2);

    subscription1->Cancel();

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(0, *callback1Called);
    EXPECT_EQ(1, *callback2Called);
}

HWTEST_F(EventBusImplTest, SubscriptionRAII_001, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callbackCalled = std::make_shared<int>(0);
    {
        auto subscription = eventBus->Subscribe(EventType::AUTH_SUCCESS,
            [callbackCalled](const EventData &data) { (*callbackCalled)++; });
        ASSERT_NE(nullptr, subscription);

        std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
        eventBus->Publish(EventType::AUTH_SUCCESS, data);
        TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
        EXPECT_EQ(1, *callbackCalled);
    }

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(1, *callbackCalled);
}

HWTEST_F(EventBusImplTest, MultipleEventTypes_001, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callback1Called = std::make_shared<bool>(false);
    auto callback2Called = std::make_shared<bool>(false);

    auto subscription1 = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [callback1Called](const EventData &data) { *callback1Called = true; });
    auto subscription2 = eventBus->Subscribe(static_cast<EventType>(2),
        [callback2Called](const EventData &data) { *callback2Called = true; });

    ASSERT_NE(nullptr, subscription1);
    ASSERT_NE(nullptr, subscription2);

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(*callback1Called);
    EXPECT_FALSE(*callback2Called);
}

HWTEST_F(EventBusImplTest, EmptyEventData_001, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto receivedData = std::make_shared<std::vector<uint8_t>>();
    auto subscription =
        eventBus->Subscribe(EventType::AUTH_SUCCESS, [receivedData](const EventData &data) { *receivedData = data; });
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> emptyData;
    eventBus->Publish(EventType::AUTH_SUCCESS, emptyData);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(receivedData->empty());
}

HWTEST_F(EventBusImplTest, LargeEventData_001, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto receivedData = std::make_shared<std::vector<uint8_t>>();
    auto subscription =
        eventBus->Subscribe(EventType::AUTH_SUCCESS, [receivedData](const EventData &data) { *receivedData = data; });
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> largeData(1024, 0xAA);
    eventBus->Publish(EventType::AUTH_SUCCESS, largeData);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(largeData, *receivedData);
}

HWTEST_F(EventBusImplTest, PersistSubscribe_001, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callbackCalled = std::make_shared<bool>(false);
    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [callbackCalled](const EventData &data) { *callbackCalled = true; });

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(EventBusImplTest, PersistSubscribe_002, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callbackCalled = std::make_shared<int>(0);
    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [callbackCalled](const EventData &data) { (*callbackCalled)++; });

    std::vector<uint8_t> data1 = { 0x01, 0x02, 0x03 };
    std::vector<uint8_t> data2 = { 0x04, 0x05, 0x06 };
    std::vector<uint8_t> data3 = { 0x07, 0x08, 0x09 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data1);
    eventBus->Publish(EventType::AUTH_SUCCESS, data2);
    eventBus->Publish(EventType::AUTH_SUCCESS, data3);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(3, *callbackCalled);
}

HWTEST_F(EventBusImplTest, PersistSubscribe_003, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callback1Called = std::make_shared<int>(0);
    auto callback2Called = std::make_shared<int>(0);
    auto callback3Called = std::make_shared<int>(0);

    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [callback1Called](const EventData &data) { (*callback1Called)++; });
    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [callback2Called](const EventData &data) { (*callback2Called)++; });
    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [callback3Called](const EventData &data) { (*callback3Called)++; });

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(1, *callback1Called);
    EXPECT_EQ(1, *callback2Called);
    EXPECT_EQ(1, *callback3Called);
}

HWTEST_F(EventBusImplTest, PersistSubscribe_004, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto receivedData = std::make_shared<std::vector<uint8_t>>();
    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [receivedData](const EventData &data) { *receivedData = data; });

    std::vector<uint8_t> expectedData = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, expectedData);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(expectedData, *receivedData);
}

HWTEST_F(EventBusImplTest, PersistSubscribe_005, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto callbackCalled = std::make_shared<bool>(false);
    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [callbackCalled](const EventData &data) { *callbackCalled = true; });

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(static_cast<EventType>(999), data);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(EventBusImplTest, PersistSubscribe_006, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto receivedData = std::make_shared<std::vector<uint8_t>>();
    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [receivedData](const EventData &data) { *receivedData = data; });

    std::vector<uint8_t> emptyData;
    eventBus->Publish(EventType::AUTH_SUCCESS, emptyData);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(receivedData->empty());
}

HWTEST_F(EventBusImplTest, PersistSubscribe_007, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto receivedData = std::make_shared<std::vector<uint8_t>>();
    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [receivedData](const EventData &data) { *receivedData = data; });

    std::vector<uint8_t> largeData(1024, 0xAA);
    eventBus->Publish(EventType::AUTH_SUCCESS, largeData);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(largeData, *receivedData);
}

HWTEST_F(EventBusImplTest, PersistSubscribe_008, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto persistCallbackCalled = std::make_shared<int>(0);
    auto normalCallbackCalled = std::make_shared<int>(0);

    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [persistCallbackCalled](const EventData &data) { (*persistCallbackCalled)++; });
    auto subscription = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [normalCallbackCalled](const EventData &data) { (*normalCallbackCalled)++; });
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(1, *persistCallbackCalled);
    EXPECT_EQ(1, *normalCallbackCalled);

    subscription->Cancel();
    eventBus->Publish(EventType::AUTH_SUCCESS, data);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(2, *persistCallbackCalled);
    EXPECT_EQ(1, *normalCallbackCalled);
}

HWTEST_F(EventBusImplTest, PersistSubscribe_009, TestSize.Level0)
{
    auto eventBus = EventBusImpl::Create();
    ASSERT_NE(nullptr, eventBus);

    auto persistCallbackCalled = std::make_shared<int>(0);
    auto normalCallbackCalled = std::make_shared<int>(0);

    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [persistCallbackCalled](const EventData &data) { (*persistCallbackCalled)++; });
    eventBus->PersistSubscribe(EventType::AUTH_SUCCESS,
        [persistCallbackCalled](const EventData &data) { (*persistCallbackCalled)++; });
    auto subscription = eventBus->Subscribe(EventType::AUTH_SUCCESS,
        [normalCallbackCalled](const EventData &data) { (*normalCallbackCalled)++; });
    ASSERT_NE(nullptr, subscription);

    std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
    eventBus->Publish(EventType::AUTH_SUCCESS, data);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(2, *persistCallbackCalled);
    EXPECT_EQ(1, *normalCallbackCalled);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
