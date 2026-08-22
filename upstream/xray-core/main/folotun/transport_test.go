// SPDX-License-Identifier: MPL-2.0

package folotun

import (
	"context"
	"io"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
)

func TestValidateEndpointAddress(t *testing.T) {
	valid := []string{"edge.example.com", "198.51.100.1", "2001:db8::1"}
	for _, address := range valid {
		if err := ValidateEndpointAddress(address); err != nil {
			t.Fatalf("ValidateEndpointAddress(%q) error = %v", address, err)
		}
	}
	invalid := []string{"", " edge.example.com", "edge/example.com", "-edge.example.com", "edge..example.com", "edge.example.com."}
	for _, address := range invalid {
		if err := ValidateEndpointAddress(address); err == nil {
			t.Fatalf("ValidateEndpointAddress(%q) unexpectedly succeeded", address)
		}
	}
}

func TestDialTCPUsesRunningXrayDispatcher(t *testing.T) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		payload, readErr := io.ReadAll(io.LimitReader(conn, 4))
		if readErr != nil {
			serverDone <- readErr
			return
		}
		_, writeErr := conn.Write(append([]byte("ok:"), payload...))
		serverDone <- writeErr
	}()

	instance := newFreedomInstance(t)
	defer instance.Close()
	port := uint16(listener.Addr().(*gonet.TCPAddr).Port)
	conn, err := DialTCP(context.Background(), instance, "127.0.0.1", port)
	common.Must(err)
	defer conn.Close()
	if _, err := conn.Write([]byte("xray")); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "ok:xray" {
		t.Fatalf("response = %q, want %q", response, "ok:xray")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialUDPUsesRunningXrayDispatcher(t *testing.T) {
	server, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.ParseIP("127.0.0.1"), Port: 0})
	common.Must(err)
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		n, remote, readErr := server.ReadFromUDP(buffer)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		_, writeErr := server.WriteToUDP(append([]byte("ok:"), buffer[:n]...), remote)
		serverDone <- writeErr
	}()

	instance := newFreedomInstance(t)
	defer instance.Close()
	conn, err := DialUDP(context.Background(), instance)
	common.Must(err)
	defer conn.Close()
	remote := server.LocalAddr().(*gonet.UDPAddr)
	if _, err := conn.WriteTo([]byte("xray"), remote); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "ok:xray" {
		t.Fatalf("response = %q, want %q", buffer[:n], "ok:xray")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func newFreedomInstance(t *testing.T) *core.Instance {
	t.Helper()
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
		}},
	}
	instance, err := core.New(config)
	common.Must(err)
	common.Must(instance.Start())
	return instance
}
