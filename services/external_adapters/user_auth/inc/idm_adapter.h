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

#ifndef COMPANION_DEVICE_AUTH_IDM_ADAPTER_H
#define COMPANION_DEVICE_AUTH_IDM_ADAPTER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "nocopyable.h"

#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using TemplateChangeCallback = std::function<void(int32_t userId, const std::vector<uint64_t> &templateIds)>;

class IIdmAdapter : public NoCopyable {
public:
    virtual ~IIdmAdapter() = default;

    virtual std::vector<uint64_t> GetUserTemplates(int32_t userId) = 0;
    virtual std::unique_ptr<Subscription> SubscribeUserTemplateChange(int32_t userId,
        TemplateChangeCallback callback) = 0;

#ifndef ENABLE_TEST
protected:
#endif
    IIdmAdapter() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_IDM_ADAPTER_H
