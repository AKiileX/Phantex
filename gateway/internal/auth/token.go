// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package auth provides token-based authentication for sensor → gateway gRPC.
//
// Phase 1: Static pre-shared token (256-bit random, loaded from config/env).
// Phase 2+: JWT tokens rotated via Vault with expiry and claims validation.
//
// The token is sent by the sensor as gRPC metadata ("authorization: Bearer <token>")
// and validated by a unary/stream interceptor on the gateway side.
package auth

import (
	"context"
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Validator validates sensor authentication tokens.
type Validator struct {
	log *zap.Logger

	// Phase 1: HMAC-hashed tokens mapped to tenant IDs.
	// Using HMAC digests normalizes all tokens to the same length,
	// eliminating the timing side channel in subtle.ConstantTimeCompare
	// that leaks token length when byte slices differ in size.
	hashedTokens map[[sha256.Size]byte]string
	hmacKey      []byte
}

// NewValidator creates a token validator.
// tokens maps pre-shared tokens to their tenant IDs.
func NewValidator(log *zap.Logger, tokens map[string]string) *Validator {
	// Generate a random HMAC key at startup for token normalization.
	hmacKey := make([]byte, 32)
	if _, err := cryptoRand.Read(hmacKey); err != nil {
		panic("auth: failed to generate HMAC key: " + err.Error())
	}

	hashed := make(map[[sha256.Size]byte]string, len(tokens))
	for token, tenantID := range tokens {
		h := hmacDigest(hmacKey, token)
		hashed[h] = tenantID
	}

	return &Validator{
		log:          log.Named("auth"),
		hashedTokens: hashed,
		hmacKey:      hmacKey,
	}
}

// hmacDigest computes HMAC-SHA256 of the token using the given key.
func hmacDigest(key []byte, token string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(token))
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

// ValidateToken checks a bearer token and returns the associated tenant ID.
// Returns an error if the token is invalid or missing.
func (v *Validator) ValidateToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	token := authHeaders[0]
	// Strip "Bearer " prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = token[7:]
	} else if strings.HasPrefix(token, "bearer ") {
		token = token[7:]
	}

	if token == "" {
		return "", status.Error(codes.Unauthenticated, "empty token")
	}

	// Constant-time token validation using HMAC digests.
	// All digests are the same length (sha256.Size), so ConstantTimeCompare
	// performs a full comparison regardless of the input token's length.
	inputDigest := hmacDigest(v.hmacKey, token)
	for knownDigest, tenantID := range v.hashedTokens {
		if hmac.Equal(inputDigest[:], knownDigest[:]) {
			return tenantID, nil
		}
	}

	v.log.Warn("authentication failed: invalid token")
	return "", status.Error(codes.Unauthenticated, "invalid token")
}

// StreamInterceptor returns a gRPC stream server interceptor that validates tokens.
func (v *Validator) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		tenantID, err := v.ValidateToken(ss.Context())
		if err != nil {
			return err
		}

		// Inject tenant ID into context for downstream handlers
		ctx := context.WithValue(ss.Context(), tenantIDKey, tenantID)
		wrapped := &wrappedStream{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

// UnaryInterceptor returns a gRPC unary server interceptor that validates tokens.
func (v *Validator) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		tenantID, err := v.ValidateToken(ctx)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, tenantIDKey, tenantID)
		return handler(ctx, req)
	}
}

// TenantIDFromContext extracts the authenticated tenant ID from context.
// Returns empty string if not authenticated (should not happen behind interceptor).
func TenantIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(tenantIDKey).(string); ok {
		return v
	}
	return ""
}

// ─── Context Key ──────────────────────────────────────────────────────────────

type contextKey int

const tenantIDKey contextKey = 1

// ─── Wrapped Stream ───────────────────────────────────────────────────────────
// wrappedStream overrides Context() to inject the authenticated tenant ID.

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}

// ─── Token Generation Helper ──────────────────────────────────────────────────

// GenerateToken creates a 256-bit (32-byte) hex-encoded token.
// Use this to generate tokens for sensor configuration.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptoRand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}
