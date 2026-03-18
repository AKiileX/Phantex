// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package grpcserver

import (
	"testing"
	"time"
)

func TestCheckRate_WithinLimit(t *testing.T) {
	s := &Server{
		maxEventsPerSec: 100,
		sensorRates:     make(map[string]*rateBucket),
	}

	if !s.checkRate("sensor-1", 50) {
		t.Error("expected rate check to pass for 50/100 events")
	}
	if !s.checkRate("sensor-1", 50) {
		t.Error("expected rate check to pass for 100/100 events")
	}
}

func TestCheckRate_ExceedsLimit(t *testing.T) {
	s := &Server{
		maxEventsPerSec: 100,
		sensorRates:     make(map[string]*rateBucket),
	}

	if !s.checkRate("sensor-1", 100) {
		t.Error("expected first batch of exactly 100 to pass")
	}
	if s.checkRate("sensor-1", 1) {
		t.Error("expected rate check to fail after exceeding 100 events/sec")
	}
}

func TestCheckRate_DifferentSensorsIndependent(t *testing.T) {
	s := &Server{
		maxEventsPerSec: 10,
		sensorRates:     make(map[string]*rateBucket),
	}

	if !s.checkRate("sensor-a", 10) {
		t.Error("sensor-a should be allowed 10 events")
	}
	if !s.checkRate("sensor-b", 10) {
		t.Error("sensor-b should independently be allowed 10 events")
	}
	if s.checkRate("sensor-a", 1) {
		t.Error("sensor-a should be over limit")
	}
}

func TestCheckRate_WindowResets(t *testing.T) {
	s := &Server{
		maxEventsPerSec: 10,
		sensorRates:     make(map[string]*rateBucket),
	}

	// Fill the window
	if !s.checkRate("sensor-1", 10) {
		t.Error("expected first batch to pass")
	}
	if s.checkRate("sensor-1", 1) {
		t.Error("expected rate check to fail at limit")
	}

	// Manually expire the window
	s.sensorRateMu.Lock()
	s.sensorRates["sensor-1"].windowEnd = time.Now().Add(-1 * time.Second)
	s.sensorRateMu.Unlock()

	// Should pass again after window expires
	if !s.checkRate("sensor-1", 5) {
		t.Error("expected rate check to pass after window reset")
	}
}

func TestCheckRate_ZeroLimit(t *testing.T) {
	s := &Server{
		maxEventsPerSec: 0, // disabled
		sensorRates:     make(map[string]*rateBucket),
	}

	if !s.checkRate("sensor-1", 9999999) {
		t.Error("expected rate check to always pass when limit is 0")
	}
}
