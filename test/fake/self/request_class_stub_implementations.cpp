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

#include <memory>
#include <optional>
#include <vector>

// Request class headers (these include all necessary dependencies)
#include "host_delegate_auth_request.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// ============ HostDelegateAuthRequest - Methods Not Implemented in Source ============
// These are the minimal stubs needed to resolve undefined references from fuzzer operations

void HostDelegateAuthRequest::HandleDeviceSelectResult(const std::vector<DeviceKey> &selectedDevices)
{
    (void)selectedDevices;
}

void HostDelegateAuthRequest::SendDelegateAuthRequest(const std::vector<uint8_t> &startDelegateAuthRequest)
{
    (void)startDelegateAuthRequest;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
