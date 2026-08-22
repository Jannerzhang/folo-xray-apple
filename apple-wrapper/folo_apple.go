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
	"encoding/json"
	"sync"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/core"
	featureStats "github.com/xtls/xray-core/features/stats"
	_ "github.com/xtls/xray-core/main/distro/folo"
)

const maxConfigBytes = 4 * 1024 * 1024

const (
	statusOK                   int32 = 0
	statusInvalidArgument      int32 = 1
	statusInvalidConfiguration int32 = 2
	statusInvalidState         int32 = 3
	statusStartFailed          int32 = 4
	statusStopFailed           int32 = 5
	statusInternalError        int32 = 6
)

const (
	stateIdle    int32 = 0
	stateRunning int32 = 1
)

var engine = struct {
	sync.Mutex
	instance  *core.Instance
	state     int32
	lastCode  int32
	lastError string
	startedAt time.Time
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
	engine.instance = instance
	engine.state = stateRunning
	engine.startedAt = time.Now()
	clearErrorLocked()
	return C.int32_t(statusOK)
}

//export FoloXrayStop
func FoloXrayStop() C.int32_t {
	engine.Lock()
	defer engine.Unlock()

	if engine.instance == nil {
		engine.state = stateIdle
		clearErrorLocked()
		return C.int32_t(statusOK)
	}
	if err := engine.instance.Close(); err != nil {
		engine.instance = nil
		engine.state = stateIdle
		return C.int32_t(setErrorLocked(statusStopFailed, "engine stop failed"))
	}
	engine.instance = nil
	engine.state = stateIdle
	engine.startedAt = time.Time{}
	clearErrorLocked()
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
