// SPDX-License-Identifier: MPL-2.0

package folotun

import (
	"bytes"
	"testing"
)

func TestPacketIOMetricsTracksOwnershipAndPressureWithoutPayload(t *testing.T) {
	var metrics PacketIOMetrics
	metrics.RecordInputAccepted(1200)
	metrics.RecordInputRejected(64)
	metrics.RecordOutputDelivered(900)
	metrics.RecordOutputDiscarded(400)
	metrics.FlowOpened()
	metrics.FlowOpened()
	metrics.FlowClosed()
	metrics.QueueEnqueued(1200)
	metrics.QueueEnqueued(900)
	metrics.QueueDequeued(1200)
	metrics.BufferAllocated(4096)
	metrics.BufferReleased(1024)

	snapshot := metrics.Snapshot()
	if snapshot.InputAcceptedPackets != 1 || snapshot.InputAcceptedBytes != 1200 {
		t.Fatalf("input snapshot = %+v", snapshot)
	}
	if snapshot.ActiveFlows != 1 || snapshot.PeakActiveFlows != 2 {
		t.Fatalf("flow snapshot = %+v", snapshot)
	}
	if snapshot.QueuePackets != 1 || snapshot.QueueBytes != 900 || snapshot.PeakQueueBytes != 2100 {
		t.Fatalf("queue snapshot = %+v", snapshot)
	}
	if snapshot.OutstandingBufferBytes != 3072 || snapshot.PeakBufferBytes != 4096 {
		t.Fatalf("buffer snapshot = %+v", snapshot)
	}

	encoded := metrics.SnapshotJSON()
	if len(encoded) > 4096 {
		t.Fatalf("diagnostics JSON is unbounded: %d", len(encoded))
	}
	for _, forbidden := range [][]byte{
		[]byte("payload"), []byte("destination"), []byte("credential"), []byte("198.51.100.1"),
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("diagnostics JSON contains forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func TestPacketIOMetricsSaturatesAndNeverUnderflows(t *testing.T) {
	var metrics PacketIOMetrics
	metrics.inputAcceptedPackets.Store(^uint64(0))
	metrics.inputAcceptedBytes.Store(^uint64(0) - 1)
	metrics.RecordInputAccepted(64)
	metrics.QueueDequeued(64)
	metrics.BufferReleased(64)

	snapshot := metrics.Snapshot()
	if snapshot.InputAcceptedPackets != ^uint64(0) || snapshot.InputAcceptedBytes != ^uint64(0) {
		t.Fatalf("counters did not saturate: %+v", snapshot)
	}
	if snapshot.QueuePackets != 0 || snapshot.QueueBytes != 0 || snapshot.OutstandingBufferBytes != 0 {
		t.Fatalf("current gauges underflowed: %+v", snapshot)
	}
}
