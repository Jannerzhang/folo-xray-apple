//go:build darwin || ios
// +build darwin ios

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"testing"
	"time"
)

func TestQUICInitialSNIReassemblerRejectsConflictingOverlapAndLimits(t *testing.T) {
	startedAt := time.Now()
	reassembler := newQUICInitialSNIReassembler(startedAt)
	if !reassembler.insert(0, []byte("hello")) {
		t.Fatal("first crypto fragment should fit")
	}
	if reassembler.insert(2, []byte("XX")) {
		t.Fatal("conflicting overlap must be rejected")
	}

	reassembler = newQUICInitialSNIReassembler(startedAt)
	reassembler.maxFragments = 1
	if !reassembler.insert(0, []byte("a")) {
		t.Fatal("first disjoint fragment should fit")
	}
	if reassembler.insert(3, []byte("b")) {
		t.Fatal("fragment range limit must be enforced")
	}
}

func TestQUICInitialSNIFailsClosedForMalformedPackets(t *testing.T) {
	if got := sniffQUICInitialSNI(nil); got != "" {
		t.Fatalf("empty packet returned SNI %q", got)
	}
	if got := sniffQUICInitialSNI([]byte{0xc0, 0, 0, 0, 1}); got != "" {
		t.Fatalf("truncated packet returned SNI %q", got)
	}
}
