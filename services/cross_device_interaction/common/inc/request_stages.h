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

#ifndef COMPANION_DEVICE_AUTH_REQUEST_STAGES_H
#define COMPANION_DEVICE_AUTH_REQUEST_STAGES_H

#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace CommonStages {
constexpr StageId WAIT_CONNECTION_OPEN = 101;
constexpr StageId DONE_CONNECTION_OPEN = 102;
} // namespace CommonStages

namespace HostDelegateAuthStages {
constexpr StageId WAIT_DELEGATE_AUTH_REPLY = 1;
constexpr StageId DONE_DELEGATE_AUTH_REPLY = 2;
constexpr StageId WAIT_DELEGATE_RESULT = 3;
constexpr StageId DONE_DELEGATE_RESULT = 4;
} // namespace HostDelegateAuthStages

namespace HostTokenAuthStages {
constexpr StageId WAIT_TOKEN_AUTH_REPLY = 1;
constexpr StageId DONE_TOKEN_AUTH_REPLY = 2;
} // namespace HostTokenAuthStages

namespace HostObtainTokenStages {
constexpr StageId WAIT_OBTAIN_TOKEN = 1;
constexpr StageId DONE_OBTAIN_TOKEN = 2;
} // namespace HostObtainTokenStages

namespace HostIssueTokenStages {
constexpr StageId WAIT_PRE_ISSUE_TOKEN_REPLY = 1;
constexpr StageId DONE_PRE_ISSUE_TOKEN_REPLY = 2;
constexpr StageId WAIT_ISSUE_TOKEN_REPLY = 3;
constexpr StageId DONE_ISSUE_TOKEN_REPLY = 4;
} // namespace HostIssueTokenStages

namespace HostAddCompanionStages {
constexpr StageId WAIT_DEVICE_SELECT = 1;
constexpr StageId DONE_DEVICE_SELECT = 2;
constexpr StageId WAIT_INIT_KEY_NEG_REPLY = 3;
constexpr StageId DONE_INIT_KEY_NEG_REPLY = 4;
constexpr StageId WAIT_BEGIN_ADD_BINDING_REPLY = 5;
constexpr StageId DONE_BEGIN_ADD_BINDING_REPLY = 6;
constexpr StageId WAIT_END_ADD_BINDING_REPLY = 7;
constexpr StageId DONE_END_ADD_BINDING_REPLY = 8;
} // namespace HostAddCompanionStages

namespace HostRemoveHostBindingStages {
constexpr StageId WAIT_REMOVE_HOST_BINDING_REPLY = 1;
constexpr StageId DONE_REMOVE_HOST_BINDING_REPLY = 2;
} // namespace HostRemoveHostBindingStages

namespace HostSyncDeviceStatusStages {
constexpr StageId WAIT_SYNC_DEVICE_STATUS_REPLY = 1;
constexpr StageId DONE_SYNC_DEVICE_STATUS_REPLY = 2;
} // namespace HostSyncDeviceStatusStages

namespace CompanionDelegateAuthStages {
constexpr StageId WAIT_USER_AUTH = 1;
constexpr StageId DONE_USER_AUTH = 2;
constexpr StageId WAIT_SEND_RESULT_REPLY = 3;
constexpr StageId DONE_SEND_RESULT_REPLY = 4;
} // namespace CompanionDelegateAuthStages

namespace CompanionObtainTokenStages {
constexpr StageId WAIT_PRE_OBTAIN_TOKEN_REPLY = 1;
constexpr StageId DONE_PRE_OBTAIN_TOKEN_REPLY = 2;
constexpr StageId WAIT_OBTAIN_TOKEN_REPLY = 3;
constexpr StageId DONE_OBTAIN_TOKEN_REPLY = 4;
} // namespace CompanionObtainTokenStages

namespace CompanionIssueTokenStages {
constexpr StageId WAIT_ISSUE_TOKEN = 1;
constexpr StageId DONE_ISSUE_TOKEN = 2;
} // namespace CompanionIssueTokenStages

namespace CompanionAddCompanionStages {
constexpr StageId WAIT_BEGIN_BINDING = 1;
constexpr StageId DONE_BEGIN_BINDING = 2;
constexpr StageId WAIT_END_BINDING = 3;
constexpr StageId DONE_END_BINDING = 4;
} // namespace CompanionAddCompanionStages

namespace CompanionRevokeTokenStages {
constexpr StageId WAIT_REVOKE_TOKEN_REPLY = 1;
constexpr StageId DONE_REVOKE_TOKEN_REPLY = 2;
} // namespace CompanionRevokeTokenStages

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_REQUEST_STAGES_H
