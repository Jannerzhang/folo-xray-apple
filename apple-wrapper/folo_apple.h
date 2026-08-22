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

// Stage-13 transport seams. These APIs operate only after FoloXrayStartJSON
// has loaded the approved managed profile. They expose bounded TCP/UDP
// sessions to the private PacketFlow adapter; they do not create listeners,
// accept generic JSON, or expose Xray's internal types.
int32_t FoloXrayTCPConnect(const uint8_t *address_bytes,
                           size_t address_length,
                           uint16_t port,
                           uint64_t *handle);
int32_t FoloXrayTCPRead(uint64_t handle,
                        uint8_t *buffer,
                        size_t capacity,
                        size_t *read_length);
int32_t FoloXrayTCPWrite(uint64_t handle,
                         const uint8_t *buffer,
                         size_t length,
                         size_t *written_length);
int32_t FoloXrayTCPClose(uint64_t handle);

int32_t FoloXrayUDPConnect(uint64_t *handle);
int32_t FoloXrayUDPRead(uint64_t handle,
                        uint8_t *buffer,
                        size_t capacity,
                        size_t *read_length,
                        uint8_t *source_address,
                        size_t source_capacity,
                        uint8_t *source_family,
                        uint16_t *source_port);
int32_t FoloXrayUDPWrite(uint64_t handle,
                         const uint8_t *buffer,
                         size_t length,
                         const uint8_t *destination_address,
                         size_t destination_length,
                         uint16_t destination_port,
                         size_t *written_length);
int32_t FoloXrayUDPClose(uint64_t handle);

char *FoloXrayCopyVersion(void);
char *FoloXrayCopyLastError(void);
char *FoloXrayCopyStatsJSON(void);
void FoloXrayFreeString(char *value);

#ifdef __cplusplus
}
#endif

#endif
