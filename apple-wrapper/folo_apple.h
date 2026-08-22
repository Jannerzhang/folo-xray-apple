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

char *FoloXrayCopyVersion(void);
char *FoloXrayCopyLastError(void);
char *FoloXrayCopyStatsJSON(void);
void FoloXrayFreeString(char *value);

#ifdef __cplusplus
}
#endif

#endif
