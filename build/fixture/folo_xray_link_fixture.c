// SPDX-License-Identifier: MPL-2.0
#include "folo_apple.h"

int main(void) {
  char *version = FoloXrayCopyVersion();
  if (version == 0) {
    return 1;
  }
  FoloXrayFreeString(version);
  return FoloXrayState() == FOLO_XRAY_STATE_IDLE ? 0 : 1;
}
