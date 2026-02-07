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

#ifndef COMPANION_DEVICE_AUTH_IAM_CHECK_H
#define COMPANION_DEVICE_AUTH_IAM_CHECK_H

#include "iam_logger.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
// these macros are used to check condition that should never fail
#define ENSURE_OR_RETURN(cond)                          \
    do {                                                \
        if (!(cond)) {                                  \
            IAM_LOGE("(" #cond ") check fail, return"); \
            return;                                     \
        }                                               \
    } while (0)

#define ENSURE_OR_RETURN_VAL(cond, retVal)              \
    do {                                                \
        if (!(cond)) {                                  \
            IAM_LOGE("(" #cond ") check fail, return"); \
            return (retVal);                            \
        }                                               \
    } while (0)

#define ENSURE_OR_CONTINUE(cond)                          \
    do {                                                  \
        if (!(cond)) {                                    \
            IAM_LOGE("(" #cond ") check fail, continue"); \
            continue;                                     \
        }                                                 \
    } while (0)

// these macros are used to check condition with description for better debugging
#define ENSURE_OR_RETURN_DESC(desc, cond)                                  \
    do {                                                                   \
        if (!(cond)) {                                                     \
            IAM_LOGE("%{public}s (" #cond ") check fail, return", (desc)); \
            return;                                                        \
        }                                                                  \
    } while (0)

#define ENSURE_OR_RETURN_DESC_VAL(desc, cond, retVal)                      \
    do {                                                                   \
        if (!(cond)) {                                                     \
            IAM_LOGE("%{public}s (" #cond ") check fail, return", (desc)); \
            return (retVal);                                               \
        }                                                                  \
    } while (0)

#define ENSURE_OR_CONTINUE_DESC(desc, cond)                                  \
    do {                                                                     \
        if (!(cond)) {                                                       \
            IAM_LOGE("%{public}s (" #cond ") check fail, continue", (desc)); \
            continue;                                                        \
        }                                                                    \
    } while (0)
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_IAM_CHECK_H
