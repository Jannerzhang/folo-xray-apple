// SPDX-License-Identifier: MPL-2.0
package folojson

import (
	"strings"
	"testing"

	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/foloinbound"
)

const validConfig = `{
  "version": 1,
  "mode": "tun",
  "outbound": {
    "address": "edge.example.com",
    "port": 443,
    "uuid": "00000000-0000-0000-0000-000000000001",
    "flow": "xtls-rprx-vision",
    "encryption": "none",
    "transport": "tcp",
    "security": "reality",
    "reality": {
      "serverName": "www.example.com",
      "fingerprint": "chrome",
      "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "shortId": "0123456789abcdef",
      "spiderX": "/"
    }
  }
}`

func TestLoadBuildsOnlyManagedOutbound(t *testing.T) {
	config, err := Load(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(config.Inbound) != 0 {
		t.Fatalf("expected no network listeners, got %d", len(config.Inbound))
	}
	if len(config.Outbound) != 1 || config.Outbound[0].Tag != "proxy" {
		t.Fatalf("unexpected outbound shape: %+v", config.Outbound)
	}
	instance, err := core.New(config)
	if err != nil {
		t.Fatalf("core.New() error = %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("core.Instance.Close() error = %v", err)
	}
}

func TestLoadRejectsLegacySurface(t *testing.T) {
	legacy := strings.Replace(validConfig, `"mode": "tun"`, `"mode": "tun", "inbounds": []`, 1)
	if _, err := Load(strings.NewReader(legacy)); err == nil {
		t.Fatal("Load() accepted an unsupported legacy field")
	}
}

func TestLoadRejectsNonRealityOutbound(t *testing.T) {
	vmess := strings.Replace(validConfig, `"security": "reality"`, `"security": "tls"`, 1)
	if _, err := Load(strings.NewReader(vmess)); err == nil {
		t.Fatal("Load() accepted a non-Reality security mode")
	}
}
