// SPDX-License-Identifier: MPL-2.0
//
// Folo's first-release distro registration. It intentionally registers only
// the VLESS/Reality data path and the services required to run a managed
// full-tunnel profile. The generic Xray JSON/legacy configuration package is
// deliberately not imported: the Folo parser is a closed schema boundary
// that prevents unrelated protocol registrations from entering the build.
package folo

import (
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/main/foloinbound"
	_ "github.com/xtls/xray-core/main/folojson"
	_ "github.com/xtls/xray-core/main/folotun"
)
