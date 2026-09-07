//go:build darwin || ios
// +build darwin ios

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/xtls/xray-core/core"
	"github.com/Jannerzhang/folo-xray-apple/apple-wrapper/router"
)

func TestNetstackDiagnostics_ConcurrencyAndRejection(t *testing.T) {
	// Create minimal core instance
	config := &core.Config{}
	instance, err := core.New(config)
	if err != nil {
		t.Fatalf("failed to create core instance: %v", err)
	}

	r := router.NewRouter(router.Config{Mode: router.ModeRule})
	runtime, err := newNetstackRuntime(instance, r)
	if err != nil {
		t.Fatalf("failed to create netstack runtime: %v", err)
	}
	defer runtime.close()

	diag := runtime.Diagnostics()
	if diag.TCPActive != 0 || diag.TCPRejected != 0 {
		t.Fatalf("initial TCP active=%d, rejected=%d (expected 0)", diag.TCPActive, diag.TCPRejected)
	}
	if diag.UDPActive != 0 || diag.UDPRejected != 0 {
		t.Fatalf("initial UDP active=%d, rejected=%d (expected 0)", diag.UDPActive, diag.UDPRejected)
	}

	// 1. Fill all TCP tokens to simulate 48 active connections
	for i := 0; i < netstackMaxConcurrentTCP; i++ {
		runtime.tcpTokens <- struct{}{}
	}

	// Next handleTCP should trigger tcpRejected
	runtime.handleTCP(&tcp.ForwarderRequest{})
	diagAfterTCP := runtime.Diagnostics()
	if diagAfterTCP.TCPRejected != 1 {
		t.Errorf("expected TCPRejected=1, got %d", diagAfterTCP.TCPRejected)
	}

	// Drain TCP tokens
	for i := 0; i < netstackMaxConcurrentTCP; i++ {
		<-runtime.tcpTokens
	}

	// 2. Fill all UDP tokens to simulate 48 active flows
	for i := 0; i < netstackMaxConcurrentUDP; i++ {
		runtime.udpTokens <- struct{}{}
	}

	// Next handleUDP should trigger udpRejected
	rejected := runtime.handleUDP(&udp.ForwarderRequest{})
	if rejected {
		t.Errorf("expected handleUDP to return false when rejected")
	}
	diagAfterUDP := runtime.Diagnostics()
	if diagAfterUDP.UDPRejected != 1 {
		t.Errorf("expected UDPRejected=1, got %d", diagAfterUDP.UDPRejected)
	}

	// Drain UDP tokens
	for i := 0; i < netstackMaxConcurrentUDP; i++ {
		<-runtime.udpTokens
	}

	// 3. Test JSON serialization and route attribution
	r.Route("www.baidu.com", net.ParseIP("180.101.50.242"), 443)
	diagWithRoute := runtime.Diagnostics()
	if diagWithRoute.RouteStats.TotalDirect == 0 {
		t.Errorf("expected RouteStats.TotalDirect > 0")
	}

	jsonBytes, err := json.Marshal(diagWithRoute)
	if err != nil {
		t.Fatalf("failed to marshal diagnostics: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal diagnostics JSON: %v", err)
	}

	if _, ok := parsed["tcpRejected"]; !ok {
		t.Errorf("missing tcpRejected in JSON")
	}
	if _, ok := parsed["udpRejected"]; !ok {
		t.Errorf("missing udpRejected in JSON")
	}
	if _, ok := parsed["gcCycleCount"]; !ok {
		t.Errorf("missing gcCycleCount in JSON")
	}
}
