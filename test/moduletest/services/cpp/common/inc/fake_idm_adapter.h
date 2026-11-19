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

#ifndef COMPANION_DEVICE_AUTH_FAKE_IDM_ADAPTER_H
#define COMPANION_DEVICE_AUTH_FAKE_IDM_ADAPTER_H

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#include "idm_adapter.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FakeIdmAdapter : public IIdmAdapter {
public:
    FakeIdmAdapter() = default;
    ~FakeIdmAdapter() override = default;

    std::vector<uint64_t> GetUserTemplates(int32_t userId) override
    {
        auto it = templates_.find(userId);
        return it != templates_.end() ? it->second : std::vector<uint64_t> {};
    }

    bool RefreshAndGetUserTemplates(int32_t userId, std::vector<uint64_t> &templateIds) override
    {
        auto it = templates_.find(userId);
        templateIds = it != templates_.end() ? it->second : std::vector<uint64_t> {};
        return true;
    }

    std::unique_ptr<Subscription> SubscribeUserTemplateChange(int32_t userId, TemplateChangeCallback callback) override
    {
        callbacks_[userId].push_back(std::move(callback));
        return std::make_unique<Subscription>([this, userId]() { callbacks_.erase(userId); });
    }

    // Test backdoors
    void TestSetUserTemplates(int32_t userId, std::vector<uint64_t> tmplIds)
    {
        templates_[userId] = std::move(tmplIds);
    }

    void TestAddTemplate(int32_t userId, uint64_t tmplId)
    {
        templates_[userId].push_back(tmplId);
    }

    void TestSimulateTemplateChange(int32_t userId, const std::vector<uint64_t> &templateIds)
    {
        auto it = callbacks_.find(userId);
        if (it != callbacks_.end()) {
            for (auto &cb : it->second) {
                cb(userId, templateIds);
            }
        }
    }

private:
    std::map<int32_t, std::vector<uint64_t>> templates_;
    std::map<int32_t, std::vector<TemplateChangeCallback>> callbacks_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_IDM_ADAPTER_H
