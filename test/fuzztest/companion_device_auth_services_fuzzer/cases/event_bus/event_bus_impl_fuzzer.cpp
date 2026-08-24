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

#include <cstdint>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "event_bus_impl.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using EventBusImplFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreate(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto eventBus = EventBusImpl::Create();
    (void)eventBus;
}

static void FuzzPublish(FuzzedDataProvider &fuzzData)
{
    uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();
    std::vector<uint8_t> eventData =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    auto eventBus = EventBusImpl::Create();
    if (eventBus) {
        EventType type = static_cast<EventType>(eventTypeValue);
        eventBus->Publish(type, eventData);
    }
    EnsureAllTaskExecuted();
}

static void FuzzSubscribe(FuzzedDataProvider &fuzzData)
{
    uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();
    std::vector<uint8_t> eventData =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    auto eventBus = EventBusImpl::Create();
    if (eventBus) {
        EventType type = static_cast<EventType>(eventTypeValue);
        auto subscription = eventBus->Subscribe(type, [&eventData](const EventData &data) { (void)data; });
        (void)subscription;
    }
}

static void FuzzSubscribeAndPublish(FuzzedDataProvider &fuzzData)
{
    uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();
    std::vector<uint8_t> eventData =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    auto eventBus = EventBusImpl::Create();
    if (eventBus) {
        EventType type = static_cast<EventType>(eventTypeValue);
        auto subscription = eventBus->Subscribe(type, [&eventData](const EventData &data) { (void)data; });
        if (subscription) {
            std::vector<uint8_t> publishData =
                fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
            eventBus->Publish(type, publishData);
        }
    }
    EnsureAllTaskExecuted();
}

static void FuzzMultipleSubscribers(FuzzedDataProvider &fuzzData)
{
    uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();
    uint32_t subscriberCount = fuzzData.ConsumeIntegralInRange<uint32_t>(1, 10);

    auto eventBus = EventBusImpl::Create();
    if (eventBus) {
        EventType type = static_cast<EventType>(eventTypeValue);
        std::vector<std::shared_ptr<Subscription>> subscriptions;

        for (uint32_t i = 0; i < subscriberCount; ++i) {
            auto subscription = eventBus->Subscribe(type, [i](const EventData &data) {
                (void)i;
                (void)data;
            });
            if (subscription) {
                subscriptions.push_back(subscription);
            }
        }

        std::vector<uint8_t> publishData =
            fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
        eventBus->Publish(type, publishData);
    }
    EnsureAllTaskExecuted();
}

static void FuzzUnsubscribe(FuzzedDataProvider &fuzzData)
{
    uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();

    auto eventBus = EventBusImpl::Create();
    if (eventBus) {
        EventType type = static_cast<EventType>(eventTypeValue);
        auto subscription = eventBus->Subscribe(type, [](const EventData &data) { (void)data; });
        if (subscription) {
            bool shouldCancel = fuzzData.ConsumeBool();
            if (shouldCancel) {
                subscription->Cancel();
            }

            std::vector<uint8_t> publishData =
                fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
            eventBus->Publish(type, publishData);
        }
    }
    EnsureAllTaskExecuted();
}

static void FuzzEventBusImplConstructor(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto eventBus = std::make_shared<EventBusImpl>();
    (void)eventBus;
}

static void DoSubscribeOperation(const std::shared_ptr<EventBusImpl> &eventBus, EventType type,
    std::vector<std::shared_ptr<Subscription>> &subscriptions)
{
    auto subscription = eventBus->Subscribe(type, [](const EventData &data) { (void)data; });
    if (subscription) {
        subscriptions.push_back(subscription);
    }
}

static void DoPublishOperation(const std::shared_ptr<EventBusImpl> &eventBus, EventType type,
    FuzzedDataProvider &fuzzData)
{
    std::vector<uint8_t> publishData =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    eventBus->Publish(type, publishData);
}

static void DoCancelOperation(std::vector<std::shared_ptr<Subscription>> &subscriptions, FuzzedDataProvider &fuzzData)
{
    if (!subscriptions.empty()) {
        size_t index = fuzzData.ConsumeIntegralInRange<size_t>(0, subscriptions.size() - 1);
        subscriptions[index]->Cancel();
    }
}

static void FuzzMixedOperations(FuzzedDataProvider &fuzzData)
{
    enum OperationType {
        OPERATION_SUBSCRIBE = 0,
        OPERATION_PUBLISH = 1,
        OPERATION_CANCEL = 2,
        OPERATION_CLEAR = 3,
        OPERATION_MAX = 3
    };

    auto eventBus = EventBusImpl::Create();
    if (!eventBus) {
        return;
    }

    uint32_t operationCount = fuzzData.ConsumeIntegralInRange<uint32_t>(1, 20);
    std::vector<std::shared_ptr<Subscription>> subscriptions;

    for (uint32_t i = 0; i < operationCount; ++i) {
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(OPERATION_SUBSCRIBE, OPERATION_MAX);
        uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();
        EventType type = static_cast<EventType>(eventTypeValue);

        switch (operation) {
            case OPERATION_SUBSCRIBE:
                DoSubscribeOperation(eventBus, type, subscriptions);
                break;
            case OPERATION_PUBLISH:
                DoPublishOperation(eventBus, type, fuzzData);
                break;
            case OPERATION_CANCEL:
                DoCancelOperation(subscriptions, fuzzData);
                break;
            case OPERATION_CLEAR:
                subscriptions.clear();
                break;
            default:
                break;
        }
    }
    EnsureAllTaskExecuted();
}

static void FuzzPersistSubscribe(FuzzedDataProvider &fuzzData)
{
    uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();
    std::vector<uint8_t> eventData =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    auto eventBus = EventBusImpl::Create();
    if (eventBus) {
        EventType type = static_cast<EventType>(eventTypeValue);
        eventBus->PersistSubscribe(type, [&eventData](const EventData &data) { (void)data; });
    }
}

static void FuzzPersistSubscribeAndPublish(FuzzedDataProvider &fuzzData)
{
    uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();
    std::vector<uint8_t> eventData =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    auto eventBus = EventBusImpl::Create();
    if (eventBus) {
        EventType type = static_cast<EventType>(eventTypeValue);
        eventBus->PersistSubscribe(type, [&eventData](const EventData &data) { (void)data; });

        std::vector<uint8_t> publishData =
            fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
        eventBus->Publish(type, publishData);
    }
    EnsureAllTaskExecuted();
}

static void FuzzMultiplePersistSubscribers(FuzzedDataProvider &fuzzData)
{
    uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();
    uint32_t subscriberCount = fuzzData.ConsumeIntegralInRange<uint32_t>(1, 10);

    auto eventBus = EventBusImpl::Create();
    if (eventBus) {
        EventType type = static_cast<EventType>(eventTypeValue);

        for (uint32_t i = 0; i < subscriberCount; ++i) {
            eventBus->PersistSubscribe(type, [i](const EventData &data) {
                (void)i;
                (void)data;
            });
        }

        std::vector<uint8_t> publishData =
            fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
        eventBus->Publish(type, publishData);
    }
    EnsureAllTaskExecuted();
}

static void DoPersistSubscribeOperation(const std::shared_ptr<EventBusImpl> &eventBus, EventType type)
{
    eventBus->PersistSubscribe(type, [](const EventData &data) { (void)data; });
}

static void FuzzMixedSubscribeTypes(FuzzedDataProvider &fuzzData)
{
    enum OperationType {
        OPERATION_SUBSCRIBE = 0,
        OPERATION_PERSIST_SUBSCRIBE = 1,
        OPERATION_PUBLISH = 2,
        OPERATION_CANCEL = 3,
        OPERATION_CLEAR = 4,
        OPERATION_MAX = 4
    };

    auto eventBus = EventBusImpl::Create();
    if (!eventBus) {
        return;
    }

    uint32_t operationCount = fuzzData.ConsumeIntegralInRange<uint32_t>(1, 20);
    std::vector<std::shared_ptr<Subscription>> subscriptions;

    for (uint32_t i = 0; i < operationCount; ++i) {
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(OPERATION_SUBSCRIBE, OPERATION_MAX);
        uint16_t eventTypeValue = fuzzData.ConsumeIntegral<uint16_t>();
        EventType type = static_cast<EventType>(eventTypeValue);

        switch (operation) {
            case OPERATION_SUBSCRIBE:
                DoSubscribeOperation(eventBus, type, subscriptions);
                break;
            case OPERATION_PERSIST_SUBSCRIBE:
                DoPersistSubscribeOperation(eventBus, type);
                break;
            case OPERATION_PUBLISH:
                DoPublishOperation(eventBus, type, fuzzData);
                break;
            case OPERATION_CANCEL:
                DoCancelOperation(subscriptions, fuzzData);
                break;
            case OPERATION_CLEAR:
                subscriptions.clear();
                break;
            default:
                break;
        }
    }
    EnsureAllTaskExecuted();
}

static const EventBusImplFuzzFunction g_fuzzFuncs[] = {
    FuzzCreate,
    FuzzPublish,
    FuzzSubscribe,
    FuzzSubscribeAndPublish,
    FuzzMultipleSubscribers,
    FuzzUnsubscribe,
    FuzzEventBusImplConstructor,
    FuzzMixedOperations,
    FuzzPersistSubscribe,
    FuzzPersistSubscribeAndPublish,
    FuzzMultiplePersistSubscribers,
    FuzzMixedSubscribeTypes,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(EventBusImplFuzzFunction);

void FuzzEventBusImpl(FuzzedDataProvider &fuzzData)
{
    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](fuzzData);
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzEventBusImpl)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
