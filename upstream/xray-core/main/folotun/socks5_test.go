// SPDX-License-Identifier: MPL-2.0
package folotun

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
)

func TestSocks5OutboundServerUsesLoopbackAndXrayDispatcher(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := upstream.Accept()
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

	instance := newSocksFreedomInstance(t)
	defer instance.Close()
	proxy, err := NewSocks5OutboundServer(instance)
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()
	addr, ok := proxy.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() || addr.Port == 0 {
		t.Fatalf("unexpected SOCKS address: %v", proxy.Addr())
	}

	client, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatal(err)
	}
	if method[0] != 0x05 || method[1] != 0x00 {
		t.Fatalf("unexpected method response: %x", method)
	}
	port := upstream.Addr().(*net.TCPAddr).Port
	request := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("SOCKS CONNECT failed: %x", reply)
	}
	if _, err := client.Write([]byte("xray")); err != nil {
		t.Fatal(err)
	}
	if tcp, ok := client.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "ok:xray" {
		t.Fatalf("response = %q", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	if err := proxy.Stop(); err != nil {
		t.Fatal(err)
	}
	stats := proxy.Stats()
	if stats.AcceptedConnections != 1 || stats.PeakConnections != 1 || stats.ActiveConnections != 0 || stats.CompletedConnections != 1 {
		t.Fatalf("unexpected socket stats: %+v", stats)
	}

}

func newSocksFreedomInstance(t *testing.T) *core.Instance {
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
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance
}
