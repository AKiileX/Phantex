// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package auth_test

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/AKiileX/Phantex/gateway/internal/auth"
)

func newTestValidator() *auth.Validator {
	log, _ := zap.NewDevelopment()
	tokens := map[string]string{
		"valid-test-token-1": "tenant-aaa",
		"valid-test-token-2": "tenant-bbb",
	}
	return auth.NewValidator(log, tokens)
}

func TestValidateToken_ValidToken(t *testing.T) {
	v := newTestValidator()
	md := metadata.New(map[string]string{"authorization": "Bearer valid-test-token-1"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	tenantID, err := v.ValidateToken(ctx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if tenantID != "tenant-aaa" {
		t.Errorf("expected tenant-aaa, got %s", tenantID)
	}
}

func TestValidateToken_SecondToken(t *testing.T) {
	v := newTestValidator()
	md := metadata.New(map[string]string{"authorization": "Bearer valid-test-token-2"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	tenantID, err := v.ValidateToken(ctx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if tenantID != "tenant-bbb" {
		t.Errorf("expected tenant-bbb, got %s", tenantID)
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	v := newTestValidator()
	md := metadata.New(map[string]string{"authorization": "Bearer wrong-token"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := v.ValidateToken(ctx)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", st.Code())
	}
}

func TestValidateToken_MissingMetadata(t *testing.T) {
	v := newTestValidator()
	ctx := context.Background() // no metadata

	_, err := v.ValidateToken(ctx)
	if err == nil {
		t.Fatal("expected error for missing metadata")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", st.Code())
	}
}

func TestValidateToken_MissingAuthHeader(t *testing.T) {
	v := newTestValidator()
	md := metadata.New(map[string]string{"other-header": "value"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := v.ValidateToken(ctx)
	if err == nil {
		t.Fatal("expected error for missing auth header")
	}
}

func TestValidateToken_EmptyBearerToken(t *testing.T) {
	v := newTestValidator()
	md := metadata.New(map[string]string{"authorization": "Bearer "})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := v.ValidateToken(ctx)
	if err == nil {
		t.Fatal("expected error for empty bearer token")
	}
}

func TestValidateToken_NoBearerPrefix(t *testing.T) {
	v := newTestValidator()
	md := metadata.New(map[string]string{"authorization": "valid-test-token-1"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	tenantID, err := v.ValidateToken(ctx)
	if err != nil {
		t.Fatalf("token without Bearer prefix should still work, got: %v", err)
	}
	if tenantID != "tenant-aaa" {
		t.Errorf("expected tenant-aaa, got %s", tenantID)
	}
}
