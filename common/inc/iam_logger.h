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

#ifndef COMPANION_DEVICE_AUTH_IAM_LOGGER_H
#define COMPANION_DEVICE_AUTH_IAM_LOGGER_H

#include "hilog/log.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
#ifdef __FILE_NAME__
#define IAM_LOG_FILE __FILE_NAME__
#else
#define IAM_LOG_FILE (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD002421

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define COMPANION_DEVICE_AUTH_DEBUG(...) HILOG_DEBUG(LOG_CORE, __VA_ARGS__)
#define COMPANION_DEVICE_AUTH_INFO(...) HILOG_INFO(LOG_CORE, __VA_ARGS__)
#define COMPANION_DEVICE_AUTH_WARN(...) HILOG_WARN(LOG_CORE, __VA_ARGS__)
#define COMPANION_DEVICE_AUTH_ERROR(...) HILOG_ERROR(LOG_CORE, __VA_ARGS__)
#define COMPANION_DEVICE_AUTH_FATAL(...) HILOG_FATAL(LOG_CORE, __VA_ARGS__)

#define ARGS(fmt, ...) "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, IAM_LOG_FILE, __LINE__, ##__VA_ARGS__
#define IAM_LOG(level, ...) COMPANION_DEVICE_AUTH_##level(ARGS(__VA_ARGS__))

#define IAM_LOGD(...) IAM_LOG(DEBUG, __VA_ARGS__)
#define IAM_LOGI(...) IAM_LOG(INFO, __VA_ARGS__)
#define IAM_LOGW(...) IAM_LOG(WARN, __VA_ARGS__)
#define IAM_LOGE(...) IAM_LOG(ERROR, __VA_ARGS__)
#define IAM_LOGF(...) IAM_LOG(FATAL, __VA_ARGS__)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_IAM_LOGGER_H
