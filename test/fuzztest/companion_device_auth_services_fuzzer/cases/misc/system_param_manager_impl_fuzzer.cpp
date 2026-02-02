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

#include <cstdint>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "singleton_manager.h"
#include "system_param_manager.h"
#include "system_param_manager_impl.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr uint32_t SIZE_64 = 64;
}

using SystemParamManagerImplFuzzFunction = void (*)(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &);

static void FuzzOp0(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetParam
    std::string key = GenerateFuzzString(fuzzData, SIZE_64);
    std::string defaultValue = GenerateFuzzString(fuzzData, SIZE_64);
    auto value = mgr->GetParam(key, defaultValue);
    (void)value;
}

static void FuzzOp1(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SetParam
    std::string key = GenerateFuzzString(fuzzData, SIZE_64);
    std::string value = GenerateFuzzString(fuzzData, SIZE_64);
    mgr->SetParam(key, value);
}

static void FuzzOp2(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SetParamTwice
    std::string key = GenerateFuzzString(fuzzData, SIZE_64);
    std::string value1 = GenerateFuzzString(fuzzData, SIZE_64);
    std::string value2 = GenerateFuzzString(fuzzData, SIZE_64);
    mgr->SetParamTwice(key, value1, value2);
}

static void FuzzOp3(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test WatchParam
    std::string key = GenerateFuzzString(fuzzData, SIZE_64);
    auto subscription = mgr->WatchParam(key, [](const std::string &value) { (void)value; });
    (void)subscription;
}

static void FuzzOp4(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test Create
    auto newMgr = SystemParamManagerImpl::Create();
    if (newMgr) {
        std::string key = GenerateFuzzString(fuzzData, SIZE_64);
        std::string defaultValue = GenerateFuzzString(fuzzData, SIZE_64);
        auto value = newMgr->GetParam(key, defaultValue);
        (void)value;
    }
}

static void FuzzOp5(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test OnParamChange (requires EnableTest)
    auto newMgr = SystemParamManagerImpl::Create();
    if (newMgr) {
        std::string key = GenerateFuzzString(fuzzData, SIZE_64);
        std::string value = GenerateFuzzString(fuzzData, SIZE_64);
        // Note: OnParamChange is internal and may not be accessible
        (void)key;
        (void)value;
    }
}

static void FuzzOp6(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SetParam followed by GetParam
    std::string key = GenerateFuzzString(fuzzData, SIZE_64);
    std::string value = GenerateFuzzString(fuzzData, SIZE_64);
    mgr->SetParam(key, value);
    auto retrieved = mgr->GetParam(key, "default");
    (void)retrieved;
}

static void FuzzOp7(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SetParamTwice followed by GetParam
    std::string key = GenerateFuzzString(fuzzData, SIZE_64);
    std::string value1 = GenerateFuzzString(fuzzData, SIZE_64);
    std::string value2 = GenerateFuzzString(fuzzData, SIZE_64);
    mgr->SetParamTwice(key, value1, value2);
    auto retrieved = mgr->GetParam(key, "default");
    (void)retrieved;
}

static void FuzzOp8(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test multiple WatchParam subscriptions
    std::string key = GenerateFuzzString(fuzzData, SIZE_64);
    auto sub1 = mgr->WatchParam(key, [](const std::string &v) { (void)v; });
    auto sub2 = mgr->WatchParam(key, [](const std::string &v) { (void)v; });
    (void)sub1;
    (void)sub2;
}

static void FuzzOp9(std::shared_ptr<ISystemParamManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test WatchParam then SetParam (trigger callback)
    std::string key = GenerateFuzzString(fuzzData, SIZE_64);
    auto subscription = mgr->WatchParam(key, [](const std::string &v) { (void)v; });
    mgr->SetParam(key, "test_value");
    (void)subscription;
}

static const SystemParamManagerImplFuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4, FuzzOp5,
    FuzzOp6, FuzzOp7, FuzzOp8, FuzzOp9 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SystemParamManagerImplFuzzFunction);

void FuzzSystemParamManagerImpl(FuzzedDataProvider &fuzzData)
{
    auto mgr = SystemParamManagerImpl::Create();
    if (!mgr) {
        return;
    }

    std::shared_ptr<ISystemParamManager> iMgr = mgr;

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](iMgr, fuzzData);

        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](iMgr, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzSystemParamManagerImpl)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
