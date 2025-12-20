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

#ifndef IPC_CLIENT_UTILS_H
#define IPC_CLIENT_UTILS_H

#include "iremote_object.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class IpcClientUtils {
public:
    static sptr<IRemoteObject> GetRemoteObject(int32_t saId);
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // IPC_CLIENT_UTILS_H