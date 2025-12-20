/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#ifndef SOFTBUS_GLOBAL_CALLBACKS_H
#define SOFTBUS_GLOBAL_CALLBACKS_H

#include <memory>

#include "soft_bus_connection_manager.h"
#include "trans_type.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

void SetGlobalSoftBusConnectionManager(std::weak_ptr<SoftBusConnectionManager> adapter);
void ClearGlobalSoftBusConnectionManager(SoftBusConnectionManager *adapter);

void SoftBusOnBind(int32_t socket, PeerSocketInfo info);
void SoftBusOnShutdown(int32_t socket, ShutdownReason reason);
void SoftBusOnBytes(int32_t socket, const void *data, uint32_t dataLen);
void SoftBusOnError(int32_t socket, int32_t errCode);
bool SoftBusOnNegotiate(int32_t socket, PeerSocketInfo info);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // SOFTBUS_GLOBAL_CALLBACKS_H
