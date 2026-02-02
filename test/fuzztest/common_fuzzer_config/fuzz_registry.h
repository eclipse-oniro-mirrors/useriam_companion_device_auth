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

#ifndef FUZZ_REGISTRY_H
#define FUZZ_REGISTRY_H

#include <cstdint>
#include <functional>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Fuzz function registry
using FuzzFunction = void (*)(FuzzedDataProvider &);

class FuzzRegistry {
public:
    static void Register(FuzzFunction func)
    {
        GetRegistry().push_back(func);
    }

    static const std::vector<FuzzFunction> &GetAllFunctions()
    {
        return GetRegistry();
    }

    static size_t GetCount()
    {
        return GetRegistry().size();
    }

private:
    static std::vector<FuzzFunction> &GetRegistry()
    {
        static std::vector<FuzzFunction> registry;
        return registry;
    }
};

// Fuzzer registration macro (uses static initialization)
// Note: Pass the full function name, e.g., FUZZ_REGISTER(FuzzSoftBusChannel)
#define FUZZ_REGISTER(func)                                                                                       \
    namespace {                                                                                                   \
    static const bool g_fuzzerRegistered_##func = []() {                                                          \
        ::OHOS::UserIam::CompanionDeviceAuth::FuzzRegistry::Register(::OHOS::UserIam::CompanionDeviceAuth::func); \
        return true;                                                                                              \
    }();                                                                                                          \
    }

// Singleton initializer registry
using SingletonInitFunction = bool (*)(FuzzedDataProvider &);

class SingletonInitRegistry {
public:
    static void Register(SingletonInitFunction func)
    {
        GetRegistry().push_back(func);
    }

    static bool InitializeAll(FuzzedDataProvider &fuzzData)
    {
        bool allSuccess = true;
        for (auto initFunc : GetRegistry()) {
            if (!initFunc(fuzzData)) {
                allSuccess = false;
            }
        }
        return allSuccess;
    }

private:
    static std::vector<SingletonInitFunction> &GetRegistry()
    {
        static std::vector<SingletonInitFunction> registry;
        return registry;
    }
};

// Singleton cleanup registry
using SingletonCleanupFunction = void (*)();

class SingletonCleanupRegistry {
public:
    static void Register(SingletonCleanupFunction func)
    {
        GetRegistry().push_back(func);
    }

    static void CleanupAll()
    {
        // Clean up in reverse order (LIFO)
        auto &registry = GetRegistry();
        for (auto it = registry.rbegin(); it != registry.rend(); ++it) {
            (*it)();
        }
    }

private:
    static std::vector<SingletonCleanupFunction> &GetRegistry()
    {
        static std::vector<SingletonCleanupFunction> registry;
        return registry;
    }
};

// Registration macros for singletons
#define REGISTER_SINGLETON_INIT(name) SingletonInitRegistry::Register(Init##name)

#define REGISTER_SINGLETON_CLEANUP(name) SingletonCleanupRegistry::Register(Cleanup##name)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // FUZZ_REGISTRY_H
