//go:build !darwin && !ios
// +build !darwin,!ios

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"errors"

	"github.com/xtls/xray-core/core"
)

const netstackMaxPacketSize = 64 * 1024

func startNetstack(*core.Instance) error {
	return errors.New("netstack is only available on Darwin and iOS")
}

func stopNetstack() {}

func writeNetstackPacket([]byte) int32 {
	return statusInvalidState
}

func readNetstackPacket([]byte) (int, int32) {
	return 0, statusInvalidState
}
