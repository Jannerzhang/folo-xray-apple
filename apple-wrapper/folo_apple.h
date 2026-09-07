// SPDX-License-Identifier: MPL-2.0
#ifndef FOLO_XRAY_APPLE_H
#define FOLO_XRAY_APPLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum FoloXrayStatusCode {
  FOLO_XRAY_OK = 0,
  FOLO_XRAY_INVALID_ARGUMENT = 1,
  FOLO_XRAY_INVALID_CONFIGURATION = 2,
  FOLO_XRAY_INVALID_STATE = 3,
  FOLO_XRAY_START_FAILED = 4,
  FOLO_XRAY_STOP_FAILED = 5,
  FOLO_XRAY_INTERNAL_ERROR = 6,
  FOLO_XRAY_IO_ERROR = 7,
  FOLO_XRAY_EOF = 8,
  FOLO_XRAY_RESOURCE_LIMIT = 9,
  FOLO_XRAY_WOULD_BLOCK = 10,
};

enum FoloXrayState {
  FOLO_XRAY_STATE_IDLE = 0,
  FOLO_XRAY_STATE_RUNNING = 1,
};

int32_t FoloXrayValidateConfigJSON(const uint8_t *config_bytes,
                                   size_t config_length);
int32_t FoloXrayStartJSON(const uint8_t *config_bytes, size_t config_length);
int32_t FoloXrayStop(void);
int32_t FoloXrayState(void);
int32_t FoloXrayLastErrorCode(void);

// Stage-10 transport PoC. The caller transfers ownership of fd after a
// successful start. The socket carries Folo PacketFlow v1 frames, not a
// generic Xray listener protocol. Stop is idempotent and closes the adopted
// endpoint exactly once.
int32_t FoloXrayPacketBridgeStart(int32_t fd);
int32_t FoloXrayPacketBridgeStop(void);
int32_t FoloXrayPacketBridgeState(void);
char *FoloXrayPacketBridgeCopyStatsJSON(void);

// Stage-14 netstack packet boundary. Start requires a running managed Xray
// instance. WritePacket copies and injects one complete IPv4/IPv6 packet;
// ReadPacket is non-blocking and returns FOLO_XRAY_WOULD_BLOCK when the
// egress queue is empty. Stop is idempotent.
int32_t FoloXrayNetstackStart(void);
int32_t FoloXrayNetstackStop(void);
int32_t FoloXrayNetstackWritePacket(const uint8_t *packet, size_t length);
int32_t FoloXrayNetstackReadPacket(uint8_t *buffer,
                                   size_t capacity,
                                   size_t *read_length);
char *FoloXrayNetstackCopyDiagnosticsJSON(void);

char *FoloXrayCopyVersion(void);
char *FoloXrayCopyLastError(void);
char *FoloXrayCopyStatsJSON(void);
void FoloXrayFreeString(char *value);

#ifdef __cplusplus
}
#endif

#endif
