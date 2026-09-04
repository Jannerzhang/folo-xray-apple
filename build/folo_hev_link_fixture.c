// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>

#include "folo_hev_packetflow.h"

int
main (void)
{
    if (FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_IDLE)
        return 1;
    if (FoloHevPacketFlowStart ((const uint8_t *)"invalid", 7, -1) !=
        FOLO_HEV_PACKETFLOW_INVALID_ARGUMENT)
        return 2;
    if (FoloHevPacketFlowStop () != FOLO_HEV_PACKETFLOW_OK)
        return 3;
    return 0;
}
