// SPDX-License-Identifier: MPL-2.0
package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"context"
	"io"
	gonet "net"
	"sync"
	"unsafe"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/folotun"
)

const (
	maxTransportPayload  = 65_535
	maxTransportSessions = 256
)

type tcpTransportSession struct {
	conn gonet.Conn
}

type udpTransportSession struct {
	conn gonet.PacketConn
}

var transportSessions = struct {
	mu   syncMutex
	next uint64
	tcp  map[uint64]*tcpTransportSession
	udp  map[uint64]*udpTransportSession
}{
	next: 1,
	tcp:  make(map[uint64]*tcpTransportSession),
	udp:  make(map[uint64]*udpTransportSession),
}

// syncMutex is a small alias kept in this file so the C ABI implementation
// has one obvious lock domain. It is backed by sync.Mutex below.
type syncMutex struct{ mu sync.Mutex }

func (m *syncMutex) Lock()   { m.mu.Lock() }
func (m *syncMutex) Unlock() { m.mu.Unlock() }

func transportAddress(address *C.uint8_t, length C.size_t) (string, int32) {
	if address == nil || length == 0 || length > C.size_t(folotun.MaxEndpointAddressLength) {
		return "", statusInvalidArgument
	}
	value := string(unsafe.Slice((*byte)(unsafe.Pointer(address)), int(length)))
	if err := folotun.ValidateEndpointAddress(value); err != nil {
		return "", statusInvalidArgument
	}
	return value, statusOK
}

func transportPayload(buffer *C.uint8_t, length C.size_t, allowEmpty bool) ([]byte, int32) {
	if length > C.size_t(maxTransportPayload) || (!allowEmpty && length == 0) {
		return nil, statusInvalidArgument
	}
	if length > 0 && buffer == nil {
		return nil, statusInvalidArgument
	}
	if length == 0 {
		return nil, statusOK
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(length)), statusOK
}

func transportEngine() (*core.Instance, int32) {
	engine.Lock()
	defer engine.Unlock()
	if engine.instance == nil || engine.state != stateRunning {
		return nil, statusInvalidState
	}
	return engine.instance, statusOK
}

func allocateTCP(conn gonet.Conn) (uint64, int32) {
	transportSessions.mu.Lock()
	defer transportSessions.mu.Unlock()
	if len(transportSessions.tcp)+len(transportSessions.udp) >= maxTransportSessions {
		return 0, statusResourceLimit
	}
	handle := transportSessions.next
	transportSessions.next++
	transportSessions.tcp[handle] = &tcpTransportSession{conn: conn}
	return handle, statusOK
}

func allocateUDP(conn gonet.PacketConn) (uint64, int32) {
	transportSessions.mu.Lock()
	defer transportSessions.mu.Unlock()
	if len(transportSessions.tcp)+len(transportSessions.udp) >= maxTransportSessions {
		return 0, statusResourceLimit
	}
	handle := transportSessions.next
	transportSessions.next++
	transportSessions.udp[handle] = &udpTransportSession{conn: conn}
	return handle, statusOK
}

func takeTCP(handle uint64) (*tcpTransportSession, bool) {
	transportSessions.mu.Lock()
	defer transportSessions.mu.Unlock()
	session, ok := transportSessions.tcp[handle]
	return session, ok
}

func takeUDP(handle uint64) (*udpTransportSession, bool) {
	transportSessions.mu.Lock()
	defer transportSessions.mu.Unlock()
	session, ok := transportSessions.udp[handle]
	return session, ok
}

func closeTCP(handle uint64) int32 {
	transportSessions.mu.Lock()
	session, ok := transportSessions.tcp[handle]
	if ok {
		delete(transportSessions.tcp, handle)
	}
	transportSessions.mu.Unlock()
	if !ok {
		return statusInvalidArgument
	}
	if err := session.conn.Close(); err != nil {
		return statusIOError
	}
	return statusOK
}

func closeUDP(handle uint64) int32 {
	transportSessions.mu.Lock()
	session, ok := transportSessions.udp[handle]
	if ok {
		delete(transportSessions.udp, handle)
	}
	transportSessions.mu.Unlock()
	if !ok {
		return statusInvalidArgument
	}
	if err := session.conn.Close(); err != nil {
		return statusIOError
	}
	return statusOK
}

func closeTransportSessions() {
	transportSessions.mu.Lock()
	tcp := make([]*tcpTransportSession, 0, len(transportSessions.tcp))
	for handle, session := range transportSessions.tcp {
		delete(transportSessions.tcp, handle)
		tcp = append(tcp, session)
	}
	udp := make([]*udpTransportSession, 0, len(transportSessions.udp))
	for handle, session := range transportSessions.udp {
		delete(transportSessions.udp, handle)
		udp = append(udp, session)
	}
	transportSessions.mu.Unlock()
	for _, session := range tcp {
		_ = session.conn.Close()
	}
	for _, session := range udp {
		_ = session.conn.Close()
	}
}

//export FoloXrayTCPConnect
func FoloXrayTCPConnect(addressBytes *C.uint8_t, addressLength C.size_t, port C.uint16_t, handle *C.uint64_t) C.int32_t {
	if handle == nil {
		return C.int32_t(statusInvalidArgument)
	}
	address, code := transportAddress(addressBytes, addressLength)
	if code != statusOK || port == 0 {
		return C.int32_t(statusInvalidArgument)
	}
	instance, code := transportEngine()
	if code != statusOK {
		return C.int32_t(code)
	}
	conn, err := folotun.DialTCP(context.Background(), instance, address, uint16(port))
	if err != nil {
		return C.int32_t(statusStartFailed)
	}
	value, code := allocateTCP(conn)
	if code != statusOK {
		_ = conn.Close()
		return C.int32_t(code)
	}
	*handle = C.uint64_t(value)
	return C.int32_t(statusOK)
}

//export FoloXrayTCPRead
func FoloXrayTCPRead(handle C.uint64_t, buffer *C.uint8_t, capacity C.size_t, readLength *C.size_t) C.int32_t {
	if readLength == nil || capacity == 0 || capacity > C.size_t(maxTransportPayload) || buffer == nil {
		return C.int32_t(statusInvalidArgument)
	}
	session, ok := takeTCP(uint64(handle))
	if !ok {
		return C.int32_t(statusInvalidArgument)
	}
	count, err := session.conn.Read(unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(capacity)))
	*readLength = C.size_t(count)
	if count > 0 {
		return C.int32_t(statusOK)
	}
	if err == io.EOF {
		return C.int32_t(statusEOF)
	}
	if err != nil {
		return C.int32_t(statusIOError)
	}
	return C.int32_t(statusIOError)
}

//export FoloXrayTCPWrite
func FoloXrayTCPWrite(handle C.uint64_t, buffer *C.uint8_t, length C.size_t, writtenLength *C.size_t) C.int32_t {
	if writtenLength == nil {
		return C.int32_t(statusInvalidArgument)
	}
	payload, code := transportPayload(buffer, length, true)
	if code != statusOK {
		return C.int32_t(code)
	}
	session, ok := takeTCP(uint64(handle))
	if !ok {
		return C.int32_t(statusInvalidArgument)
	}
	total := 0
	for len(payload) > 0 {
		count, err := session.conn.Write(payload)
		total += count
		payload = payload[count:]
		if err != nil {
			*writtenLength = C.size_t(total)
			return C.int32_t(statusIOError)
		}
		if count == 0 {
			*writtenLength = C.size_t(total)
			return C.int32_t(statusIOError)
		}
	}
	*writtenLength = C.size_t(total)
	return C.int32_t(statusOK)
}

//export FoloXrayTCPClose
func FoloXrayTCPClose(handle C.uint64_t) C.int32_t {
	return C.int32_t(closeTCP(uint64(handle)))
}

//export FoloXrayUDPConnect
func FoloXrayUDPConnect(handle *C.uint64_t) C.int32_t {
	if handle == nil {
		return C.int32_t(statusInvalidArgument)
	}
	instance, code := transportEngine()
	if code != statusOK {
		return C.int32_t(code)
	}
	conn, err := folotun.DialUDP(context.Background(), instance)
	if err != nil {
		return C.int32_t(statusStartFailed)
	}
	value, code := allocateUDP(conn)
	if code != statusOK {
		_ = conn.Close()
		return C.int32_t(code)
	}
	*handle = C.uint64_t(value)
	return C.int32_t(statusOK)
}

//export FoloXrayUDPRead
func FoloXrayUDPRead(handle C.uint64_t, buffer *C.uint8_t, capacity C.size_t, readLength *C.size_t, sourceAddress *C.uint8_t, sourceCapacity C.size_t, sourceFamily *C.uint8_t, sourcePort *C.uint16_t) C.int32_t {
	if readLength == nil || sourceFamily == nil || sourcePort == nil || sourceAddress == nil || sourceCapacity < 16 || capacity == 0 || capacity > C.size_t(maxTransportPayload) || buffer == nil {
		return C.int32_t(statusInvalidArgument)
	}
	*readLength = 0
	session, ok := takeUDP(uint64(handle))
	if !ok {
		return C.int32_t(statusInvalidArgument)
	}
	count, address, err := session.conn.ReadFrom(unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(capacity)))
	*readLength = C.size_t(count)
	if err != nil {
		return C.int32_t(statusIOError)
	}
	udpAddress, ok := address.(*gonet.UDPAddr)
	if !ok || udpAddress == nil {
		return C.int32_t(statusIOError)
	}
	if ip := udpAddress.IP.To4(); ip != nil {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(sourceAddress)), 4), ip)
		*sourceFamily = 4
	} else if ip := udpAddress.IP.To16(); ip != nil {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(sourceAddress)), 16), ip)
		*sourceFamily = 6
	} else {
		return C.int32_t(statusIOError)
	}
	*sourcePort = C.uint16_t(udpAddress.Port)
	return C.int32_t(statusOK)
}

//export FoloXrayUDPWrite
func FoloXrayUDPWrite(handle C.uint64_t, buffer *C.uint8_t, length C.size_t, destinationAddress *C.uint8_t, destinationLength C.size_t, destinationPort C.uint16_t, writtenLength *C.size_t) C.int32_t {
	if writtenLength == nil || destinationAddress == nil || destinationLength == 0 || destinationPort == 0 {
		return C.int32_t(statusInvalidArgument)
	}
	payload, code := transportPayload(buffer, length, false)
	if code != statusOK {
		return C.int32_t(code)
	}
	address, code := transportAddress(destinationAddress, destinationLength)
	if code != statusOK {
		return C.int32_t(code)
	}
	ip := gonet.ParseIP(address)
	if ip == nil {
		return C.int32_t(statusInvalidArgument)
	}
	session, ok := takeUDP(uint64(handle))
	if !ok {
		return C.int32_t(statusInvalidArgument)
	}
	count, err := session.conn.WriteTo(payload, &gonet.UDPAddr{IP: ip, Port: int(destinationPort)})
	*writtenLength = C.size_t(count)
	if err != nil {
		return C.int32_t(statusIOError)
	}
	return C.int32_t(statusOK)
}

//export FoloXrayUDPClose
func FoloXrayUDPClose(handle C.uint64_t) C.int32_t {
	return C.int32_t(closeUDP(uint64(handle)))
}
