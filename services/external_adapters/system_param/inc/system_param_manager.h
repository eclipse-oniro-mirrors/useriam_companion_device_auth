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

#ifndef COMPANION_DEVICE_AUTH_SYSTEM_PARAM_MANAGER_H
#define COMPANION_DEVICE_AUTH_SYSTEM_PARAM_MANAGER_H

#include <functional>
#include <memory>
#include <string>

#include "nocopyable.h"

#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

inline constexpr const char *TRUE_STR = "true";
inline constexpr const char *FALSE_STR = "false";

inline constexpr const char *CDA_IS_AUTH_MAINTAIN_ACTIVE_KEY = "companiondeviceauth.isAuthMaintainActive";
inline constexpr const char *CDA_IS_FUNCTION_READY_KEY = "companiondeviceauth.isFunctionReady";

using SystemParamCallback = std::function<void(const std::string &value)>;

class ISystemParamManager : public NoCopyable {
public:
    virtual ~ISystemParamManager() = default;

    virtual std::string GetParam(const std::string &key, const std::string &defaultValue) = 0;
    virtual void SetParam(const std::string &key, const std::string &value) = 0;
    virtual void SetParamTwice(const std::string &key, const std::string &value1, const std::string &value2) = 0;
    virtual std::unique_ptr<Subscription> WatchParam(const std::string &key, SystemParamCallback &&callback) = 0;
    virtual void OnParamChange(const std::string &key, const std::string &value) = 0;

protected:
    ISystemParamManager() = default;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SYSTEM_PARAM_MANAGER_H
