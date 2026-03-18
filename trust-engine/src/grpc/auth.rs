// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//! API-key interceptor for gRPC.
//!
//! When an API key is configured, every incoming request must include
//! `x-api-key` metadata matching the configured value.  If no key is
//! configured, all requests are allowed (development mode).

use tonic::{Request, Status};

/// Creates an interceptor closure that validates the `x-api-key` header.
///
/// If `api_key` is `None`, the interceptor is a no-op (all requests pass).
pub fn api_key_interceptor(
    api_key: Option<String>,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone + Send + Sync + 'static {
    move |req: Request<()>| {
        if let Some(ref expected) = api_key {
            match req.metadata().get("x-api-key") {
                Some(val) => {
                    let provided = val
                        .to_str()
                        .map_err(|_| Status::unauthenticated("Invalid API key encoding"))?;
                    if provided != expected.as_str() {
                        return Err(Status::unauthenticated("Invalid API key"));
                    }
                }
                None => {
                    return Err(Status::unauthenticated("Missing x-api-key metadata"));
                }
            }
        }
        // No key configured or key matched → allow request.
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    #[test]
    fn test_no_key_configured_allows_all() {
        let interceptor = api_key_interceptor(None);
        let req = Request::new(());
        assert!(interceptor(req).is_ok());
    }

    #[test]
    fn test_correct_key_allows() {
        let interceptor = api_key_interceptor(Some("secret-123".into()));
        let mut req = Request::new(());
        req.metadata_mut()
            .insert("x-api-key", MetadataValue::from_static("secret-123"));
        assert!(interceptor(req).is_ok());
    }

    #[test]
    fn test_wrong_key_rejects() {
        let interceptor = api_key_interceptor(Some("secret-123".into()));
        let mut req = Request::new(());
        req.metadata_mut()
            .insert("x-api-key", MetadataValue::from_static("wrong-key"));
        let err = interceptor(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_missing_key_rejects() {
        let interceptor = api_key_interceptor(Some("secret-123".into()));
        let req = Request::new(());
        let err = interceptor(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
