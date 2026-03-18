// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package sdksocket

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// uuidV7 generates a UUID v7 (time-ordered, random tail).
// Identical to converter.uuidV7 but kept local to avoid cyclic imports.
func uuidV7() string {
	var uuid [16]byte

	ms := uint64(time.Now().UnixMilli())
	uuid[0] = byte(ms >> 40)
	uuid[1] = byte(ms >> 32)
	uuid[2] = byte(ms >> 24)
	uuid[3] = byte(ms >> 16)
	uuid[4] = byte(ms >> 8)
	uuid[5] = byte(ms)

	rand.Read(uuid[6:]) //nolint:errcheck

	uuid[6] = (uuid[6] & 0x0F) | 0x70 // version 7
	uuid[8] = (uuid[8] & 0x3F) | 0x80 // variant 10

	return fmt.Sprintf(
		"%s-%s-%s-%s-%s",
		hex.EncodeToString(uuid[0:4]),
		hex.EncodeToString(uuid[4:6]),
		hex.EncodeToString(uuid[6:8]),
		hex.EncodeToString(uuid[8:10]),
		hex.EncodeToString(uuid[10:16]),
	)
}
