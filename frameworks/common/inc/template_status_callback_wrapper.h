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

#ifndef TEMPLATE_STATUS_CALLBACK_WRAPPER_H
#define TEMPLATE_STATUS_CALLBACK_WRAPPER_H

#include "itemplate_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
template <typename T>
class TemplateStatusCallbackWrapper : public ITemplateStatusCallback {
public:
    TemplateStatusCallbackWrapper(T callback) : callback_(callback)
    {
    }
    ~TemplateStatusCallbackWrapper() = default;

    void OnTemplateStatusChange(const std::vector<ClientTemplateStatus> templateStatusList) override;

    bool operator==(const TemplateStatusCallbackWrapper &other) const
    {
        return callback_ == other.GetCallback();
    }
    const T &GetCallback() const
    {
        return callback_;
    }

private:
    T callback_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // TEMPLATE_STATUS_CALLBACK_WRAPPER_H