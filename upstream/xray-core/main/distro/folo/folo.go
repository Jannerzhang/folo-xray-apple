// SPDX-License-Identifier: MPL-2.0
//
// Folo's managed distro registration. The versioned Folo JSON boundary keeps
// VLESS/Reality as the first-release default and permits separately gated
// Trojan TCP/TLS and VMess AEAD/TCP/TLS candidates without importing generic
// Xray configuration.
package folo

import (
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/main/foloinbound"
	_ "github.com/xtls/xray-core/main/folojson"
	_ "github.com/xtls/xray-core/main/folotun"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
)
