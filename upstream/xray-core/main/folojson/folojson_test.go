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

const validTrojanConfig = `{
  "version": 2,
  "mode": "tun",
  "outbound": {
    "protocol": "trojan",
    "address": "edge.example.com",
    "port": 443,
    "password": "lease-password",
    "transport": "tcp",
    "security": "tls",
    "serverName": "edge.example.com"
  }
}`

const validVMessConfig = `{
  "version": 3,
  "mode": "tun",
  "outbound": {
    "protocol": "vmess",
    "address": "edge.vmess.example.com",
    "port": 443,
    "uuid": "00000000-0000-0000-0000-000000000001",
    "encryption": "auto",
    "transport": "tcp",
    "security": "tls",
    "serverName": "edge.vmess.example.com"
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

func TestLoadBuildsManagedTrojanOutbound(t *testing.T) {
	config, err := Load(strings.NewReader(validTrojanConfig))
	if err != nil {
		t.Fatalf("Load() Trojan error = %v", err)
	}
	if len(config.Inbound) != 0 {
		t.Fatalf("expected no network listeners, got %d", len(config.Inbound))
	}
	if len(config.Outbound) != 1 || config.Outbound[0].Tag != "proxy" {
		t.Fatalf("unexpected Trojan outbound shape: %+v", config.Outbound)
	}
	instance, err := core.New(config)
	if err != nil {
		t.Fatalf("core.New() Trojan error = %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("core.Instance.Close() Trojan error = %v", err)
	}
}

func TestLoadRejectsUnsafeTrojanSurface(t *testing.T) {
	for name, candidate := range map[string]string{
		"wrong-version":  strings.Replace(validTrojanConfig, `"version": 2`, `"version": 1`, 1),
		"wrong-security": strings.Replace(validTrojanConfig, `"security": "tls"`, `"security": "none"`, 1),
		"vless-field":    strings.Replace(validTrojanConfig, `"password": "lease-password"`, `"password": "lease-password", "uuid": "00000000-0000-0000-0000-000000000001"`, 1),
		"empty-password": strings.Replace(validTrojanConfig, `"password": "lease-password"`, `"password": ""`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(candidate)); err == nil {
				t.Fatal("Load() accepted an unsafe Trojan profile")
			}
		})
	}
}

func TestLoadBuildsManagedVMessOutbound(t *testing.T) {
	config, err := Load(strings.NewReader(validVMessConfig))
	if err != nil {
		t.Fatalf("Load() VMess error = %v", err)
	}
	if len(config.Inbound) != 0 {
		t.Fatalf("expected no network listeners, got %d", len(config.Inbound))
	}
	if len(config.Outbound) != 1 || config.Outbound[0].Tag != "proxy" {
		t.Fatalf("unexpected VMess outbound shape: %+v", config.Outbound)
	}
	instance, err := core.New(config)
	if err != nil {
		t.Fatalf("core.New() VMess error = %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("core.Instance.Close() VMess error = %v", err)
	}
}

func TestLoadRejectsUnsafeVMessSurface(t *testing.T) {
	for name, candidate := range map[string]string{
		"wrong-version":      strings.Replace(validVMessConfig, `"version": 3`, `"version": 2`, 1),
		"wrong-security":     strings.Replace(validVMessConfig, `"security": "tls"`, `"security": "none"`, 1),
		"legacy-alter-id":    strings.Replace(validVMessConfig, `"encryption": "auto"`, `"encryption": "auto", "alterId": 64`, 1),
		"unknown-encryption": strings.Replace(validVMessConfig, `"encryption": "auto"`, `"encryption": "none"`, 1),
		"reality-field":      strings.Replace(validVMessConfig, `"serverName": "edge.vmess.example.com"`, `"serverName": "edge.vmess.example.com", "reality": {}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(candidate)); err == nil {
				t.Fatal("Load() accepted an unsafe VMess profile")
			}
		})
	}
}
