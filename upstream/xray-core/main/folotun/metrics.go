// SPDX-License-Identifier: MPL-2.0
//
// Packet-I/O metrics are intentionally independent from Xray routing and
// packet contents. They provide bounded counters for the Hev evaluation
// adapter and can be sampled without taking a data-plane lock.
package folotun

import (
	"encoding/json"
	"sync/atomic"
)

const maxPacketIOMetricsUint64 = ^uint64(0)

// PacketIOMetrics records ownership and pressure events at the packet
// boundary. Every counter saturates at MaxUint64; current values never go
// below zero. A snapshot is an inexpensive, non-transactional view of the
// counters and is suitable for diagnostics, not billing or accounting.
type PacketIOMetrics struct {
	inputAcceptedPackets atomic.Uint64
	inputAcceptedBytes   atomic.Uint64
	inputRejectedPackets atomic.Uint64
	inputRejectedBytes   atomic.Uint64

	outputDeliveredPackets atomic.Uint64
	outputDeliveredBytes   atomic.Uint64
	outputDiscardedPackets atomic.Uint64
	outputDiscardedBytes   atomic.Uint64

	activeFlows     atomic.Uint64
	peakActiveFlows atomic.Uint64

	queuePackets     atomic.Uint64
	queueBytes       atomic.Uint64
	peakQueuePackets atomic.Uint64
	peakQueueBytes   atomic.Uint64

	outstandingBufferBytes atomic.Uint64
	peakBufferBytes        atomic.Uint64
	bufferAllocations      atomic.Uint64
	bufferReleases         atomic.Uint64
}

// PacketIOMetricsSnapshot is deliberately data-free: it contains no packet,
// address, destination, profile, credential, or identifier fields.
type PacketIOMetricsSnapshot struct {
	InputAcceptedPackets uint64 `json:"input_accepted_packets"`
	InputAcceptedBytes   uint64 `json:"input_accepted_bytes"`
	InputRejectedPackets uint64 `json:"input_rejected_packets"`
	InputRejectedBytes   uint64 `json:"input_rejected_bytes"`

	OutputDeliveredPackets uint64 `json:"output_delivered_packets"`
	OutputDeliveredBytes   uint64 `json:"output_delivered_bytes"`
	OutputDiscardedPackets uint64 `json:"output_discarded_packets"`
	OutputDiscardedBytes   uint64 `json:"output_discarded_bytes"`

	ActiveFlows     uint64 `json:"active_flows"`
	PeakActiveFlows uint64 `json:"peak_active_flows"`

	QueuePackets     uint64 `json:"queue_packets"`
	QueueBytes       uint64 `json:"queue_bytes"`
	PeakQueuePackets uint64 `json:"peak_queue_packets"`
	PeakQueueBytes   uint64 `json:"peak_queue_bytes"`

	OutstandingBufferBytes uint64 `json:"outstanding_buffer_bytes"`
	PeakBufferBytes        uint64 `json:"peak_buffer_bytes"`
	BufferAllocations      uint64 `json:"buffer_allocations"`
	BufferReleases         uint64 `json:"buffer_releases"`
}

func (m *PacketIOMetrics) RecordInputAccepted(packetBytes uint64) {
	addSaturating(&m.inputAcceptedPackets, 1)
	addSaturating(&m.inputAcceptedBytes, packetBytes)
}

func (m *PacketIOMetrics) RecordInputRejected(packetBytes uint64) {
	addSaturating(&m.inputRejectedPackets, 1)
	addSaturating(&m.inputRejectedBytes, packetBytes)
}

func (m *PacketIOMetrics) RecordOutputDelivered(packetBytes uint64) {
	addSaturating(&m.outputDeliveredPackets, 1)
	addSaturating(&m.outputDeliveredBytes, packetBytes)
}

func (m *PacketIOMetrics) RecordOutputDiscarded(packetBytes uint64) {
	addSaturating(&m.outputDiscardedPackets, 1)
	addSaturating(&m.outputDiscardedBytes, packetBytes)
}

func (m *PacketIOMetrics) FlowOpened() {
	addSaturating(&m.activeFlows, 1)
	setMax(&m.peakActiveFlows, m.activeFlows.Load())
}

func (m *PacketIOMetrics) FlowClosed() {
	subFloor(&m.activeFlows, 1)
}

func (m *PacketIOMetrics) QueueEnqueued(packetBytes uint64) {
	addSaturating(&m.queuePackets, 1)
	addSaturating(&m.queueBytes, packetBytes)
	setMax(&m.peakQueuePackets, m.queuePackets.Load())
	setMax(&m.peakQueueBytes, m.queueBytes.Load())
}

func (m *PacketIOMetrics) QueueDequeued(packetBytes uint64) {
	subFloor(&m.queuePackets, 1)
	subFloor(&m.queueBytes, packetBytes)
}

func (m *PacketIOMetrics) BufferAllocated(bytes uint64) {
	addSaturating(&m.bufferAllocations, 1)
	addSaturating(&m.outstandingBufferBytes, bytes)
	setMax(&m.peakBufferBytes, m.outstandingBufferBytes.Load())
}

func (m *PacketIOMetrics) BufferReleased(bytes uint64) {
	addSaturating(&m.bufferReleases, 1)
	subFloor(&m.outstandingBufferBytes, bytes)
}

func (m *PacketIOMetrics) Snapshot() PacketIOMetricsSnapshot {
	return PacketIOMetricsSnapshot{
		InputAcceptedPackets:   m.inputAcceptedPackets.Load(),
		InputAcceptedBytes:     m.inputAcceptedBytes.Load(),
		InputRejectedPackets:   m.inputRejectedPackets.Load(),
		InputRejectedBytes:     m.inputRejectedBytes.Load(),
		OutputDeliveredPackets: m.outputDeliveredPackets.Load(),
		OutputDeliveredBytes:   m.outputDeliveredBytes.Load(),
		OutputDiscardedPackets: m.outputDiscardedPackets.Load(),
		OutputDiscardedBytes:   m.outputDiscardedBytes.Load(),
		ActiveFlows:            m.activeFlows.Load(),
		PeakActiveFlows:        m.peakActiveFlows.Load(),
		QueuePackets:           m.queuePackets.Load(),
		QueueBytes:             m.queueBytes.Load(),
		PeakQueuePackets:       m.peakQueuePackets.Load(),
		PeakQueueBytes:         m.peakQueueBytes.Load(),
		OutstandingBufferBytes: m.outstandingBufferBytes.Load(),
		PeakBufferBytes:        m.peakBufferBytes.Load(),
		BufferAllocations:      m.bufferAllocations.Load(),
		BufferReleases:         m.bufferReleases.Load(),
	}
}

// SnapshotJSON returns a small, stable diagnostics representation. The
// snapshot schema is finite, so its encoded size is bounded independently of
// packet or destination data. The fallback is retained for forward safety.
func (m *PacketIOMetrics) SnapshotJSON() []byte {
	encoded, err := json.Marshal(m.Snapshot())
	if err != nil || len(encoded) > 4096 {
		return []byte(`{"metrics_error":"encoding_failed"}`)
	}
	return encoded
}

func addSaturating(value *atomic.Uint64, delta uint64) {
	for {
		current := value.Load()
		if maxPacketIOMetricsUint64-current < delta {
			if value.CompareAndSwap(current, maxPacketIOMetricsUint64) {
				return
			}
			continue
		}
		if value.CompareAndSwap(current, current+delta) {
			return
		}
	}
}

func subFloor(value *atomic.Uint64, delta uint64) {
	for {
		current := value.Load()
		next := uint64(0)
		if current > delta {
			next = current - delta
		}
		if value.CompareAndSwap(current, next) {
			return
		}
	}
}

func setMax(value *atomic.Uint64, candidate uint64) {
	for {
		current := value.Load()
		if candidate <= current || value.CompareAndSwap(current, candidate) {
			return
		}
	}
}
