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

// Fake implementation of SoftBus socket functions for unit tests

#include "socket.h"

extern "C" {
int Socket(SocketInfo info)
{
    (void)info;
    return 1; // Return fake socket ID
}

int BindAsync(int socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    (void)socket;
    (void)qos;
    (void)qosCount;
    (void)listener;
    return 0; // Success
}

int Listen(int socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    (void)socket;
    (void)qos;
    (void)qosCount;
    (void)listener;
    return 0; // Success
}

void Shutdown(int socket)
{
    (void)socket;
}

int SendBytes(int socket, const void *data, uint32_t len)
{
    (void)socket;
    (void)data;
    return static_cast<int>(len);
}
} // extern "C"
