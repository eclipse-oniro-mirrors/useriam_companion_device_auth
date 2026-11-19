/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#ifndef SOFTBUS_CHANNEL_COMMON_H
#define SOFTBUS_CHANNEL_COMMON_H

#include <cstdint>

#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

inline constexpr const char *PKG_NAME = "ohos.companiondeviceauth";
inline constexpr const char *SERVER_SOCKET_NAME = "ohos.companiondeviceauth.server";
inline constexpr const char *CLIENT_SOCKET_NAME_PREFIX = "ohos.companiondeviceauth.";
inline constexpr uint32_t PENDING_ARBITRATION_TIMEOUT_MS = 35000; // 35 seconds
constexpr Atl SOFT_BUS_CHANNEL_DEFAULT_AUTH_TRUST_LEVEL = ATL4;

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // SOFTBUS_CHANNEL_COMMON_H
