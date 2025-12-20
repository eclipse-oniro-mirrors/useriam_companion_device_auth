/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMPANION_AUTH_INTERFACE_ADAPTER_H
#define COMPANION_AUTH_INTERFACE_ADAPTER_H

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CompanionAuthInterfaceAdapter {
public:
    explicit CompanionAuthInterfaceAdapter() = default;
    virtual ~CompanionAuthInterfaceAdapter() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_AUTH_INTERFACE_ADAPTER_H
