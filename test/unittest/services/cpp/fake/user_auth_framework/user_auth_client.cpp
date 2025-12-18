/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <atomic>
#include <memory>

#include "user_auth_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class UserAuthClientImpl : public UserAuthClient {
public:
    uint64_t BeginWidgetAuth(const WidgetAuthParam &, const WidgetParam &,
        const std::shared_ptr<AuthenticationCallback> &) override
    {
        return nextContextId_.fetch_add(1, std::memory_order_relaxed);
    }

    int32_t CancelAuthentication(uint64_t) override
    {
        return 0;
    }

private:
    std::atomic<uint64_t> nextContextId_ { 1 };
};
} // namespace

UserAuthClient &UserAuthClient::GetInstance()
{
    static UserAuthClientImpl instance;
    return instance;
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
