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
#include <vector>

#include "socket.h"
#include "softbus_bus_center.h"

namespace {
// Test-controllable node basic info list returned by the fake GetAllNodeDeviceInfo.
std::vector<NodeBasicInfo> g_fakeNodeBasicInfos;
} // namespace

// Test-only helpers to control the fake node info list.
extern "C" void SetFakeNodeBasicInfos(const NodeBasicInfo *infos, int32_t infoNum)
{
    if (infos == nullptr || infoNum <= 0) {
        g_fakeNodeBasicInfos.clear();
        return;
    }
    g_fakeNodeBasicInfos.assign(infos, infos + infoNum);
}

extern "C" void ClearFakeNodeBasicInfos()
{
    g_fakeNodeBasicInfos.clear();
}

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

int GetAllNodeDeviceInfo(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum)
{
    (void)pkgName;
    if (info == nullptr || infoNum == nullptr || g_fakeNodeBasicInfos.empty()) {
        return -1; // No node info available: callers must fail open
    }
    *info = g_fakeNodeBasicInfos.data();
    *infoNum = static_cast<int32_t>(g_fakeNodeBasicInfos.size());
    return 0; // Success
}

void FreeNodeInfo(NodeBasicInfo *info)
{
    (void)info; // The buffer is owned by the test-side vector
}
} // extern "C"
