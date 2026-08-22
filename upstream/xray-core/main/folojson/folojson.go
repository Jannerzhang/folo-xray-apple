// SPDX-License-Identifier: MPL-2.0
//
// Folo's first-release configuration boundary. This package intentionally
// accepts a small, versioned schema instead of the generic Xray JSON format.
// Keeping the parser here avoids importing infra/conf, whose single Go
// package contains legacy protocols and server-side configuration builders.
package folojson

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessoutbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

const (
	formatName       = "JSON"
	maxConfigBytes   = 4 * 1024 * 1024
	firstReleaseVer  = 1
	trojanProfileVer = 2
	realityKeyLength = 32
	shortIDLength    = 8
)

// Config is the only JSON shape accepted by the Folo first-release wrapper.
// It is deliberately not an alias for Xray's generic configuration format.
type Config struct {
	Version  int      `json:"version"`
	Mode     string   `json:"mode"`
	Outbound Outbound `json:"outbound"`
}

type Outbound struct {
	Protocol   string  `json:"protocol,omitempty"`
	Address    string  `json:"address"`
	Port       uint16  `json:"port"`
	UUID       string  `json:"uuid"`
	Password   string  `json:"password"`
	Flow       string  `json:"flow"`
	Encryption string  `json:"encryption"`
	Transport  string  `json:"transport"`
	Security   string  `json:"security"`
	ServerName string  `json:"serverName"`
	Reality    Reality `json:"reality"`
}

type Reality struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

// Load registers a strict Folo JSON parser with the Xray core config API.
// Only io.Reader is supported in the iOS wrapper; file and command-line
// loading deliberately remain outside the mobile ABI.
func Load(input interface{}) (*core.Config, error) {
	reader, ok := input.(io.Reader)
	if !ok {
		return nil, errors.New("Folo JSON loader accepts only an io.Reader")
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxConfigBytes+1))
	if err != nil {
		return nil, errors.New("failed to read Folo configuration").Base(err)
	}
	if len(data) == 0 || len(data) > maxConfigBytes {
		return nil, errors.New("Folo configuration is empty or too large")
	}

	var inputConfig Config
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inputConfig); err != nil {
		return nil, errors.New("failed to decode Folo configuration").Base(err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("Folo configuration contains trailing data")
		}
		return nil, errors.New("failed to decode trailing Folo configuration data").Base(err)
	}

	return inputConfig.Build()
}

func (c Config) Build() (*core.Config, error) {
	if c.Version != firstReleaseVer && c.Version != trojanProfileVer {
		return nil, errors.New("unsupported Folo configuration version")
	}
	if c.Mode != "tun" {
		return nil, errors.New("Folo first release requires mode=tun")
	}
	if c.Version == trojanProfileVer && c.Outbound.Protocol != "trojan" {
		return nil, errors.New("Folo Trojan configuration requires protocol=trojan")
	}
	if c.Version == firstReleaseVer && c.Outbound.Protocol != "" {
		return nil, errors.New("Folo VLESS configuration does not accept a protocol discriminator")
	}

	outbound, err := c.Outbound.Build()
	if err != nil {
		return nil, err
	}

	return &core.Config{
		// The Packet Tunnel owns the TUN file descriptor. Xray receives
		// already-adapted traffic through the dispatcher and therefore has no
		// network listener in this first-release configuration.
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&stats.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{outbound},
	}, nil
}

func (o Outbound) Build() (*core.OutboundHandlerConfig, error) {
	if o.Protocol == "trojan" {
		return o.buildTrojan()
	}
	return o.buildVless()
}

func (o Outbound) buildVless() (*core.OutboundHandlerConfig, error) {
	if strings.TrimSpace(o.Address) == "" || len(o.Address) > 253 {
		return nil, errors.New("VLESS address is required")
	}
	if o.Port == 0 {
		return nil, errors.New("VLESS port is out of range")
	}
	if net.ParseAddress(o.Address) == nil {
		return nil, errors.New("VLESS address is invalid")
	}
	parsedUUID, err := uuid.ParseString(o.UUID)
	if err != nil {
		return nil, errors.New("VLESS UUID is invalid").Base(err)
	}
	if o.Flow != vless.XRV {
		return nil, errors.New("Folo first release requires xtls-rprx-vision")
	}
	if o.Encryption != "none" {
		return nil, errors.New("Folo first release requires VLESS encryption=none")
	}
	if o.Transport != "tcp" || o.Security != "reality" {
		return nil, errors.New("Folo first release supports only TCP plus Reality")
	}

	realitySettings, err := o.Reality.Build()
	if err != nil {
		return nil, err
	}
	streamSettings := &internet.StreamConfig{
		ProtocolName: "tcp",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(&tcp.Config{}),
		}},
		SecurityType: serial.GetMessageType(realitySettings),
		SecuritySettings: []*serial.TypedMessage{
			serial.ToTypedMessage(realitySettings),
		},
	}

	account := &vless.Account{
		Id:         parsedUUID.String(),
		Flow:       o.Flow,
		Encryption: o.Encryption,
	}
	endpoint := &protocol.ServerEndpoint{
		Address: net.NewIPOrDomain(net.ParseAddress(o.Address)),
		Port:    uint32(o.Port),
		User: []*protocol.User{{
			Account: serial.ToTypedMessage(account),
		}},
	}

	return &core.OutboundHandlerConfig{
		Tag: "proxy",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
			StreamSettings: streamSettings,
		}),
		ProxySettings: serial.ToTypedMessage(&vlessoutbound.Config{
			Vnext: []*protocol.ServerEndpoint{endpoint},
		}),
	}, nil
}

func (o Outbound) buildTrojan() (*core.OutboundHandlerConfig, error) {
	if strings.TrimSpace(o.Address) == "" || len(o.Address) > 253 {
		return nil, errors.New("Trojan address is required")
	}
	if o.Port == 0 {
		return nil, errors.New("Trojan port is out of range")
	}
	if net.ParseAddress(o.Address) == nil {
		return nil, errors.New("Trojan address is invalid")
	}
	if strings.TrimSpace(o.Password) == "" || len(o.Password) > 256 {
		return nil, errors.New("Trojan password is invalid")
	}
	if !validServerName(o.ServerName) {
		return nil, errors.New("Trojan serverName is invalid")
	}
	if o.Transport != "tcp" || o.Security != "tls" {
		return nil, errors.New("Folo Trojan supports only TCP plus TLS")
	}
	if o.UUID != "" || o.Flow != "" || o.Encryption != "" || o.Reality != (Reality{}) {
		return nil, errors.New("Trojan configuration contains VLESS or Reality fields")
	}

	streamSettings := &internet.StreamConfig{
		ProtocolName: "tcp",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(&tcp.Config{}),
		}},
		SecurityType: serial.GetMessageType(&tls.Config{}),
		SecuritySettings: []*serial.TypedMessage{
			serial.ToTypedMessage(&tls.Config{
				ServerName: o.ServerName,
				MinVersion: "1.2",
				MaxVersion: "1.3",
			}),
		},
	}
	account := &trojan.Account{Password: o.Password}
	endpoint := &protocol.ServerEndpoint{
		Address: net.NewIPOrDomain(net.ParseAddress(o.Address)),
		Port:    uint32(o.Port),
		User: []*protocol.User{{
			Account: serial.ToTypedMessage(account),
		}},
	}

	return &core.OutboundHandlerConfig{
		Tag: "proxy",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
			StreamSettings: streamSettings,
		}),
		ProxySettings: serial.ToTypedMessage(&trojan.ClientConfig{
			Server: []*protocol.ServerEndpoint{endpoint},
		}),
	}, nil
}

func validServerName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/ ") {
		return false
	}
	if net.ParseAddress(value) != nil {
		return true
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char == '-' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
				return false
			}
		}
	}
	return true
}

func (r Reality) Build() (*reality.Config, error) {
	if strings.TrimSpace(r.ServerName) == "" || len(r.ServerName) > 253 {
		return nil, errors.New("Reality serverName is required")
	}
	if strings.TrimSpace(r.Fingerprint) == "" {
		return nil, errors.New("Reality fingerprint is required")
	}
	publicKey, err := decodeURLBase64(r.PublicKey)
	if err != nil || len(publicKey) != realityKeyLength {
		return nil, errors.New("Reality publicKey must decode to 32 bytes")
	}
	shortID, err := hex.DecodeString(r.ShortID)
	if err != nil || len(shortID) != shortIDLength {
		return nil, errors.New("Reality shortId must be 16 hexadecimal characters")
	}

	return &reality.Config{
		ServerName:  r.ServerName,
		Fingerprint: r.Fingerprint,
		PublicKey:   publicKey,
		ShortId:     shortID,
		SpiderX:     r.SpiderX,
	}, nil
}

func decodeURLBase64(value string) ([]byte, error) {
	decoders := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, decoder := range decoders {
		decoded, err := decoder.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("invalid base64 value: %w", lastErr)
}

func init() {
	common.Must(core.RegisterConfigLoader(&core.ConfigFormat{
		Name:      formatName,
		Extension: []string{"json"},
		Loader:    Load,
	}))
}
