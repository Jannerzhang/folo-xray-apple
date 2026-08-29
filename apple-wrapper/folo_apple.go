// SPDX-License-Identifier: MPL-2.0
package main

/*
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
	"unsafe"

	"github.com/Jannerzhang/folo-xray-apple/apple-wrapper/router"
	"github.com/xtls/xray-core/core"
	featureStats "github.com/xtls/xray-core/features/stats"
	_ "github.com/xtls/xray-core/main/distro/folo"
	"github.com/xtls/xray-core/main/folotun"
)

var scavengerOnce sync.Once

const scavengerInterval = 15 * time.Second

func startScavenger() {
	scavengerOnce.Do(func() {
		go func() {
			// FreeOSMemory can briefly stop the world. Keep it out of the
			// packet hot path while still returning idle Go pages periodically
			// for the NetworkExtension memory budget.
			ticker := time.NewTicker(scavengerInterval)
			defer ticker.Stop()
			for range ticker.C {
				debug.FreeOSMemory()
			}
		}()
	})
}

func init() {
	// Restrict Go runtime threads and memory footprint for iOS NetworkExtension Jetsam limits
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(8 * 1024 * 1024)
	debug.SetGCPercent(10)
	startScavenger()
}

const maxConfigBytes = 4 * 1024 * 1024

const (
	statusOK                   int32 = 0
	statusInvalidArgument      int32 = 1
	statusInvalidConfiguration int32 = 2
	statusInvalidState         int32 = 3
	statusStartFailed          int32 = 4
	statusStopFailed           int32 = 5
	statusInternalError        int32 = 6
	statusIOError              int32 = 7
	statusEOF                  int32 = 8
	statusResourceLimit        int32 = 9
	statusWouldBlock           int32 = 10
)

const (
	stateIdle    int32 = 0
	stateRunning int32 = 1
)

var engine = struct {
	sync.Mutex
	instance     *core.Instance
	routerConfig router.Config
	state        int32
	lastCode     int32
	lastError    string
	startedAt    time.Time
}{
	state:        stateIdle,
	lastCode:     statusOK,
	lastError:    "ok",
	routerConfig: router.Config{Mode: router.ModeRule},
}

var packetBridge = struct {
	sync.Mutex
	socket     *folotun.PacketSocket
	cancel     context.CancelFunc
	done       chan error
	generation uint64
	state      int32
	lastCode   int32
	lastError  string
	framesIn   uint64
	framesOut  uint64
	bytesIn    uint64
	bytesOut   uint64
}{
	state:     stateIdle,
	lastCode:  statusOK,
	lastError: "ok",
}

func setErrorLocked(code int32, message string) int32 {
	engine.lastCode = code
	engine.lastError = message
	return code
}

func clearErrorLocked() {
	engine.lastCode = statusOK
	engine.lastError = "ok"
}

func setPacketBridgeErrorLocked(code int32, message string) int32 {
	packetBridge.lastCode = code
	packetBridge.lastError = message
	return code
}

func clearPacketBridgeErrorLocked() {
	packetBridge.lastCode = statusOK
	packetBridge.lastError = "ok"
}

func copyConfig(configBytes *C.uint8_t, configLength C.size_t) ([]byte, int32) {
	if configBytes == nil || configLength == 0 || configLength > maxConfigBytes {
		return nil, statusInvalidArgument
	}
	length := int(configLength)
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(configBytes)), length)...), statusOK
}

func loadConfig(configBytes []byte) error {
	_, err := core.LoadConfig("json", bytes.NewReader(configBytes))
	return err
}

//export FoloXrayPacketBridgeStart
func FoloXrayPacketBridgeStart(fd C.int32_t) C.int32_t {
	socket, err := folotun.NewPacketSocketFromFD(int(fd))
	if err != nil {
		packetBridge.Lock()
		defer packetBridge.Unlock()
		return C.int32_t(setPacketBridgeErrorLocked(statusInvalidArgument, "packet socket rejected"))
	}

	packetBridge.Lock()
	if packetBridge.socket != nil || packetBridge.state == stateRunning {
		packetBridge.Unlock()
		_ = socket.Close()
		return C.int32_t(statusInvalidState)
	}
	ctx, cancel := context.WithCancel(context.Background())
	packetBridge.generation++
	generation := packetBridge.generation
	done := make(chan error, 1)
	packetBridge.socket = socket
	packetBridge.cancel = cancel
	packetBridge.done = done
	packetBridge.state = stateRunning
	packetBridge.framesIn = 0
	packetBridge.framesOut = 0
	packetBridge.bytesIn = 0
	packetBridge.bytesOut = 0
	clearPacketBridgeErrorLocked()
	packetBridge.Unlock()

	go func() {
		err := socket.Echo(ctx, func(packet folotun.Packet) error {
			packetBridge.Lock()
			packetBridge.framesIn++
			packetBridge.bytesIn += uint64(len(packet.Payload))
			packetBridge.Unlock()

			if err := socket.WritePacket(packet.Payload); err != nil {
				return err
			}
			packetBridge.Lock()
			packetBridge.framesOut++
			packetBridge.bytesOut += uint64(len(packet.Payload))
			packetBridge.Unlock()
			return nil
		})
		_ = socket.Close()
		done <- err

		packetBridge.Lock()
		defer packetBridge.Unlock()
		if packetBridge.generation != generation {
			return
		}
		packetBridge.socket = nil
		packetBridge.cancel = nil
		packetBridge.done = nil
		packetBridge.state = stateIdle
		if err != nil && ctx.Err() == nil {
			setPacketBridgeErrorLocked(statusInternalError, "packet bridge terminated")
		}
	}()

	return C.int32_t(statusOK)
}

//export FoloXrayPacketBridgeStop
func FoloXrayPacketBridgeStop() C.int32_t {
	packetBridge.Lock()
	if packetBridge.socket == nil {
		packetBridge.state = stateIdle
		clearPacketBridgeErrorLocked()
		packetBridge.Unlock()
		return C.int32_t(statusOK)
	}
	socket := packetBridge.socket
	cancel := packetBridge.cancel
	done := packetBridge.done
	cancel()
	packetBridge.Unlock()

	_ = socket.Close()
	if done != nil {
		<-done
	}

	packetBridge.Lock()
	packetBridge.socket = nil
	packetBridge.cancel = nil
	packetBridge.done = nil
	packetBridge.state = stateIdle
	clearPacketBridgeErrorLocked()
	packetBridge.Unlock()
	return C.int32_t(statusOK)
}

//export FoloXrayPacketBridgeState
func FoloXrayPacketBridgeState() C.int32_t {
	packetBridge.Lock()
	defer packetBridge.Unlock()
	return C.int32_t(packetBridge.state)
}

type packetBridgeStats struct {
	State     int32  `json:"state"`
	FramesIn  uint64 `json:"framesIn"`
	FramesOut uint64 `json:"framesOut"`
	BytesIn   uint64 `json:"bytesIn"`
	BytesOut  uint64 `json:"bytesOut"`
	LastError string `json:"lastError"`
}

//export FoloXrayPacketBridgeCopyStatsJSON
func FoloXrayPacketBridgeCopyStatsJSON() *C.char {
	packetBridge.Lock()
	defer packetBridge.Unlock()
	payload, err := json.Marshal(packetBridgeStats{
		State:     packetBridge.state,
		FramesIn:  packetBridge.framesIn,
		FramesOut: packetBridge.framesOut,
		BytesIn:   packetBridge.bytesIn,
		BytesOut:  packetBridge.bytesOut,
		LastError: packetBridge.lastError,
	})
	if err != nil {
		return C.CString(`{"state":0,"lastError":"unknown"}`)
	}
	return C.CString(string(payload))
}

//export FoloXrayNetstackStart
func FoloXrayNetstackStart() C.int32_t {
	engine.Lock()
	defer engine.Unlock()
	if engine.instance == nil || engine.state != stateRunning {
		return C.int32_t(setErrorLocked(statusInvalidState, "engine is not running"))
	}
	r := router.NewRouter(engine.routerConfig)
	if err := startNetstack(engine.instance, r); err != nil {
		return C.int32_t(setErrorLocked(statusStartFailed, "netstack start failed"))
	}
	clearErrorLocked()
	return C.int32_t(statusOK)
}

//export FoloXrayNetstackStop
func FoloXrayNetstackStop() C.int32_t {
	stopNetstack()
	engine.Lock()
	clearErrorLocked()
	engine.Unlock()
	return C.int32_t(statusOK)
}

//export FoloXrayNetstackWritePacket
func FoloXrayNetstackWritePacket(packet *C.uint8_t, length C.size_t) C.int32_t {
	if packet == nil || length == 0 || length > netstackMaxPacketSize {
		return C.int32_t(statusInvalidArgument)
	}
	bytes := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(packet)), int(length))...)
	return C.int32_t(writeNetstackPacket(bytes))
}

//export FoloXrayNetstackReadPacket
func FoloXrayNetstackReadPacket(buffer *C.uint8_t, capacity C.size_t, readLength *C.size_t) C.int32_t {
	if readLength == nil || buffer == nil || capacity == 0 || capacity > netstackMaxPacketSize {
		return C.int32_t(statusInvalidArgument)
	}
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(capacity))
	length, code := readNetstackPacket(bytes)
	*readLength = C.size_t(length)
	return C.int32_t(code)
}

//export FoloXrayValidateConfigJSON
func FoloXrayValidateConfigJSON(configBytes *C.uint8_t, configLength C.size_t) C.int32_t {
	engine.Lock()
	defer engine.Unlock()

	config, code := copyConfig(configBytes, configLength)
	if code != statusOK {
		return C.int32_t(setErrorLocked(code, "configuration bytes are empty or too large"))
	}
	if err := loadConfig(config); err != nil {
		return C.int32_t(setErrorLocked(statusInvalidConfiguration, "configuration rejected"))
	}
	clearErrorLocked()
	return C.int32_t(statusOK)
}

//export FoloXrayStartJSON
func FoloXrayStartJSON(configBytes *C.uint8_t, configLength C.size_t) C.int32_t {
	engine.Lock()
	defer engine.Unlock()

	if engine.instance != nil || engine.state == stateRunning {
		return C.int32_t(setErrorLocked(statusInvalidState, "engine is already running"))
	}
	config, code := copyConfig(configBytes, configLength)
	if code != statusOK {
		return C.int32_t(setErrorLocked(code, "configuration bytes are empty or too large"))
	}
	parsed, err := core.LoadConfig("json", bytes.NewReader(config))
	if err != nil {
		return C.int32_t(setErrorLocked(statusInvalidConfiguration, "configuration rejected"))
	}
	instance, err := core.New(parsed)
	if err != nil {
		return C.int32_t(setErrorLocked(statusStartFailed, "engine creation failed"))
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return C.int32_t(setErrorLocked(statusStartFailed, "engine start failed"))
	}

	var parsedRouting struct {
		Routing *router.Config `json:"routing"`
	}
	_ = json.Unmarshal(config, &parsedRouting)
	if parsedRouting.Routing != nil {
		engine.routerConfig = *parsedRouting.Routing
	} else {
		engine.routerConfig = router.Config{Mode: router.ModeRule}
	}

	engine.instance = instance
	engine.state = stateRunning
	engine.startedAt = time.Now()
	clearErrorLocked()
	runtime.GC()
	debug.FreeOSMemory()
	return C.int32_t(statusOK)
}

//export FoloXrayStop
func FoloXrayStop() C.int32_t {
	engine.Lock()
	defer engine.Unlock()

	if engine.instance == nil {
		engine.state = stateIdle
		clearErrorLocked()
		runtime.GC()
		debug.FreeOSMemory()
		return C.int32_t(statusOK)
	}
	stopNetstack()
	if err := engine.instance.Close(); err != nil {
		engine.instance = nil
		engine.state = stateIdle
		runtime.GC()
		debug.FreeOSMemory()
		return C.int32_t(setErrorLocked(statusStopFailed, "engine stop failed"))
	}
	engine.instance = nil
	engine.state = stateIdle
	engine.startedAt = time.Time{}
	clearErrorLocked()
	runtime.GC()
	debug.FreeOSMemory()
	return C.int32_t(statusOK)
}

//export FoloXrayState
func FoloXrayState() C.int32_t {
	engine.Lock()
	defer engine.Unlock()
	return C.int32_t(engine.state)
}

//export FoloXrayLastErrorCode
func FoloXrayLastErrorCode() C.int32_t {
	engine.Lock()
	defer engine.Unlock()
	return C.int32_t(engine.lastCode)
}

//export FoloXrayCopyVersion
func FoloXrayCopyVersion() *C.char {
	return C.CString(core.Version())
}

//export FoloXrayCopyLastError
func FoloXrayCopyLastError() *C.char {
	engine.Lock()
	defer engine.Unlock()
	return C.CString(engine.lastError)
}

type statsSnapshot struct {
	State         int32            `json:"state"`
	Version       string           `json:"version"`
	UptimeSeconds int64            `json:"uptimeSeconds"`
	Counters      map[string]int64 `json:"counters,omitempty"`
}

//export FoloXrayCopyStatsJSON
func FoloXrayCopyStatsJSON() *C.char {
	engine.Lock()
	defer engine.Unlock()

	snapshot := statsSnapshot{
		State:    engine.state,
		Version:  core.Version(),
		Counters: map[string]int64{},
	}
	if engine.state == stateRunning && !engine.startedAt.IsZero() {
		snapshot.UptimeSeconds = int64(time.Since(engine.startedAt).Seconds())
	}
	if engine.instance != nil {
		if manager, ok := engine.instance.GetFeature(featureStats.ManagerType()).(featureStats.Manager); ok {
			for _, name := range []string{
				"inbound>>>folo-tun>>>traffic>>>uplink",
				"inbound>>>folo-tun>>>traffic>>>downlink",
			} {
				if counter := manager.GetCounter(name); counter != nil {
					snapshot.Counters[name] = counter.Value()
				}
			}
		}
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return C.CString(`{"state":0,"version":"unknown"}`)
	}
	return C.CString(string(payload))
}

//export FoloXrayFreeString
func FoloXrayFreeString(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}

func main() {}
