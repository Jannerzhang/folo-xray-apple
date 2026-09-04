// SPDX-License-Identifier: Apache-2.0
#ifndef FOLO_HEV_PACKETFLOW_H
#define FOLO_HEV_PACKETFLOW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__)
#define FOLO_HEV_API __attribute__((visibility("default")))
#else
#define FOLO_HEV_API
#endif

enum FoloHevPacketFlowStatus {
  FOLO_HEV_PACKETFLOW_OK = 0,
  FOLO_HEV_PACKETFLOW_INVALID_ARGUMENT = 1,
  FOLO_HEV_PACKETFLOW_INVALID_STATE = 2,
  FOLO_HEV_PACKETFLOW_START_FAILED = 3,
  FOLO_HEV_PACKETFLOW_STOP_FAILED = 4,
  FOLO_HEV_PACKETFLOW_WOULD_BLOCK = 5,
};

enum FoloHevPacketFlowState {
  FOLO_HEV_PACKETFLOW_IDLE = 0,
  FOLO_HEV_PACKETFLOW_STARTING = 1,
  FOLO_HEV_PACKETFLOW_RUNNING = 2,
  FOLO_HEV_PACKETFLOW_DRAINING = 3,
};

/*
 * Start Hev over an already-created public PacketFlow stream endpoint. The
 * endpoint is adopted only after a successful return; no tunnel descriptor is
 * opened or discovered by this API. The configuration is a bounded Hev
 * evaluation profile whose SOCKS5 endpoint must be supplied by the caller.
 */
FOLO_HEV_API int32_t FoloHevPacketFlowStart(const uint8_t *config_bytes,
                                            size_t config_length,
                                            int32_t packet_endpoint_fd);
FOLO_HEV_API int32_t FoloHevPacketFlowStop(void);
FOLO_HEV_API int32_t FoloHevPacketFlowState(void);

#ifdef __cplusplus
}
#endif

#endif
