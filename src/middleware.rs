//! Analytics middleware for automatic request tracking

use crate::{Analytics, AnalyticsConfig, ErrorRecord, RequestRecord};
use armature_core::{Error, HttpRequest, HttpResponse, Middleware, Next};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

/// Middleware that automatically records analytics for all requests
///
/// # Example
///
/// ```rust,ignore
/// use armature_analytics::{Analytics, AnalyticsMiddleware, AnalyticsConfig};
/// use armature_core::Application;
///
/// let analytics = Analytics::new(AnalyticsConfig::default());
///
/// let app = Application::new(container, router)
///     .middleware(AnalyticsMiddleware::new(analytics.clone()));
/// ```
#[derive(Clone)]
pub struct AnalyticsMiddleware {
    analytics: Analytics,
}

impl AnalyticsMiddleware {
    /// Create a new analytics middleware
    pub fn new(analytics: Analytics) -> Self {
        Self { analytics }
    }

    /// Get a reference to the analytics instance
    pub fn analytics(&self) -> &Analytics {
        &self.analytics
    }
}

/// Request context for tracking within handlers
#[derive(Clone)]
pub struct AnalyticsContext {
    analytics: Analytics,
    start_time: Instant,
    method: String,
    path: String,
}

impl AnalyticsContext {
    /// Create a new analytics context
    pub fn new(analytics: Analytics, method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            analytics,
            start_time: Instant::now(),
            method: method.into(),
            path: path.into(),
        }
    }

    /// Get elapsed time since request start
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Complete the request tracking
    pub fn complete(self, status: u16, response_size: Option<u64>) {
        let record = RequestRecord::new(
            &self.method,
            normalize_path(&self.path),
            status,
            self.start_time.elapsed(),
        )
        .with_response_size(response_size.unwrap_or(0));

        self.analytics.record_request(record);
    }

    /// Record an error during request processing
    pub fn record_error(&self, error_type: &str, message: &str) {
        let record = ErrorRecord::new(error_type, message)
            .with_endpoint(format!("{} {}", self.method, self.path));

        self.analytics.record_error(record);
    }
}

/// Anonymize a client address: IPv4 is truncated to its `/24` network and
/// IPv6 to its `/48`, so the recorded value identifies a network rather than a
/// person.
///
/// # Examples
///
/// ```
/// use armature_analytics::anonymize_ip;
///
/// assert_eq!(anonymize_ip("203.0.113.77".parse().unwrap()), "203.0.113.0/24");
/// assert_eq!(anonymize_ip("2001:db8:abcd:12::1".parse().unwrap()), "2001:db8:abcd::/48");
/// ```
pub fn anonymize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{}/24", Ipv4Addr::new(a, b, c, 0))
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped address is an IPv4 client; truncate it as one.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return anonymize_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            format!("{}/48", Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0))
        }
    }
}

/// Anonymize a client identifier if it is an IP address; other identifiers
/// are returned unchanged.
pub fn anonymize_client_id(client_id: &str) -> String {
    match client_id.trim().parse::<IpAddr>() {
        Ok(ip) => anonymize_ip(ip),
        Err(_) => client_id.to_string(),
    }
}

/// Extract a client identifier from a request for per-client tracking.
///
/// 1. The configured [`AnalyticsConfig::client_id_header`], if any — never a
///    hard-coded header the end client could set.
/// 2. Otherwise the client address from
///    [`HttpRequest::client_address`] at the configured
///    [`AnalyticsConfig::trusted_proxy_depth`] (socket peer at depth `0`),
///    anonymized unless [`AnalyticsConfig::anonymize_client_ips`] is off.
///
/// Returns `None` when nothing trustworthy is available.
fn extract_client_id(req: &HttpRequest, config: &AnalyticsConfig) -> Option<String> {
    if let Some(header) = &config.client_id_header {
        return req
            .headers
            .get(header)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned);
    }
    let ip = req.client_address(config.trusted_proxy_depth)?;
    Some(if config.anonymize_client_ips {
        anonymize_ip(ip)
    } else {
        ip.to_string()
    })
}

/// Sorted, de-duplicated query parameter names — never values.
fn query_keys(req: &HttpRequest) -> Vec<String> {
    let mut keys: Vec<String> = req.query().iter().map(|(k, _)| k.to_string()).collect();
    keys.sort();
    keys.dedup();
    keys
}

#[async_trait]
impl Middleware for AnalyticsMiddleware {
    async fn handle(&self, req: HttpRequest, next: Next) -> Result<HttpResponse, Error> {
        let config = self.analytics.config();

        // When analytics is disabled, act as a transparent pass-through.
        if !config.enabled {
            return next(req).await;
        }

        let method = req.method_str().to_owned();

        // Exclusion and sampling gate what we record, but never what we return.
        // Evaluate them first, before any normalization or allocation, so that
        // excluded/unsampled requests skip the expensive path-normalization and
        // query/client-id work entirely.
        //
        // `path_only`, not `path`: the raw target still carries the query
        // string. Keeping it would defeat both the exclusion prefixes and the
        // `:id` normalization, and would make the endpoint key unique per query
        // string — letting a caller flood the capped endpoint table.
        let excluded = config.should_exclude(req.path_only());
        if excluded || !config.should_sample() {
            return next(req).await;
        }

        // Build the recording path (before `req` is consumed by `next`).
        // Optionally fold query parameters into the tracked path.
        let mut tracked_path = normalize_path(req.path_only());
        if config.include_query_params && !req.query().is_empty() {
            tracked_path = format!("{}?{}", tracked_path, query_keys(&req).join("&"));
        }

        // Capture the client id only when client tracking is enabled.
        let client_id = if config.track_clients {
            extract_client_id(&req, config)
        } else {
            None
        };

        let start = Instant::now();
        let result = next(req).await;
        let duration = start.elapsed();

        match &result {
            Ok(response) => {
                let mut record =
                    RequestRecord::new(method, tracked_path, response.status, duration)
                        .with_response_size(response.body.len() as u64);
                if let Some(cid) = client_id {
                    record = record.with_client_id(cid);
                }
                self.analytics.record_request(record);
            }
            Err(err) => {
                // A middleware-level failure never produced a response; record
                // it as a 500 and capture the error for the error metrics.
                let mut record = RequestRecord::new(&method, tracked_path.clone(), 500, duration);
                if let Some(cid) = client_id {
                    record = record.with_client_id(cid);
                }
                self.analytics.record_request(record);
                self.analytics.record_error(
                    ErrorRecord::new("middleware_error", err.to_string())
                        .with_status(500)
                        .with_endpoint(format!("{} {}", method, tracked_path)),
                );
            }
        }

        result
    }
}

/// Helper to normalize request paths for aggregation
///
/// Converts paths like `/users/123/posts/456` to `/users/:id/posts/:id`
pub fn normalize_path(path: &str) -> String {
    // Write directly into a single pre-sized buffer, pushing either the
    // borrowed segment or the `:id` placeholder, instead of allocating an
    // intermediate `Vec<&str>`, a `Vec<String>` (one heap String per segment)
    // and a joined String.
    let mut out = String::with_capacity(path.len());
    for (i, segment) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if segment.is_empty() {
            // Preserve empty segments (leading/trailing/double slashes).
        } else if is_likely_id(segment) {
            out.push_str(":id");
        } else {
            out.push_str(segment);
        }
    }
    out
}

/// Check if a path segment is likely an ID
fn is_likely_id(segment: &str) -> bool {
    // Check for UUID pattern
    if segment.len() == 36 && segment.chars().filter(|c| *c == '-').count() == 4 {
        return true;
    }

    // Check for numeric ID
    if segment.chars().all(|c| c.is_ascii_digit()) && !segment.is_empty() {
        return true;
    }

    // Check for hex IDs (like MongoDB ObjectId)
    if segment.len() == 24 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnalyticsConfig;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/users/123/posts"), "/users/:id/posts");
        assert_eq!(normalize_path("/api/v1/users"), "/api/v1/users");
        assert_eq!(
            normalize_path("/users/550e8400-e29b-41d4-a716-446655440000"),
            "/users/:id"
        );
        assert_eq!(
            normalize_path("/items/507f1f77bcf86cd799439011"),
            "/items/:id"
        );
    }

    #[test]
    fn test_is_likely_id() {
        assert!(is_likely_id("123"));
        assert!(is_likely_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_likely_id("507f1f77bcf86cd799439011"));
        assert!(!is_likely_id("users"));
        assert!(!is_likely_id("api"));
    }

    #[test]
    fn test_analytics_context() {
        let analytics = Analytics::new(AnalyticsConfig::default());
        let ctx = AnalyticsContext::new(analytics.clone(), "GET", "/api/users");

        std::thread::sleep(std::time::Duration::from_millis(10));

        assert!(ctx.elapsed().as_millis() >= 10);
    }

    // Regression: AnalyticsMiddleware must implement armature_core::Middleware so
    // that a request flowing through the chain automatically records analytics.
    // Previously it implemented no trait and nothing was recorded unless the
    // caller manually invoked record_*.
    #[tokio::test]
    async fn test_middleware_records_automatically() {
        use std::future::Future;
        use std::pin::Pin;

        let analytics = Analytics::new(AnalyticsConfig::default());
        let mw = AnalyticsMiddleware::new(analytics.clone());

        let req = HttpRequest::new("GET", "/api/users/123".to_string());
        let next: Next = Box::new(|_req: HttpRequest| {
            Box::pin(async { Ok(HttpResponse::ok().with_body(b"hello".to_vec())) })
                as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        });

        let resp = mw.handle(req, next).await.unwrap();
        assert_eq!(resp.status, 200);

        let snapshot = analytics.snapshot();
        assert_eq!(
            snapshot.requests.total, 1,
            "middleware must record the request"
        );
        assert_eq!(snapshot.requests.success, 1);
        // Path must be normalized for aggregation.
        assert_eq!(snapshot.endpoints.len(), 1);
        assert_eq!(snapshot.endpoints[0].path, "/api/users/:id");
        // Response size captured from the body.
        assert_eq!(snapshot.throughput.total_bytes_transferred, 5);
    }

    #[tokio::test]
    async fn test_middleware_respects_disabled_and_exclusions() {
        use std::future::Future;
        use std::pin::Pin;

        // Disabled: nothing recorded, response still flows.
        let analytics = Analytics::new(AnalyticsConfig::builder().enabled(false).build());
        let mw = AnalyticsMiddleware::new(analytics.clone());
        let req = HttpRequest::new("GET", "/api/x".to_string());
        let next: Next = Box::new(|_req: HttpRequest| {
            Box::pin(async { Ok(HttpResponse::ok()) })
                as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        });
        let resp = mw.handle(req, next).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(analytics.snapshot().requests.total, 0);

        // Excluded path: not recorded.
        let analytics = Analytics::new(AnalyticsConfig::default());
        let mw = AnalyticsMiddleware::new(analytics.clone());
        let req = HttpRequest::new("GET", "/health".to_string());
        let next: Next = Box::new(|_req: HttpRequest| {
            Box::pin(async { Ok(HttpResponse::ok()) })
                as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        });
        mw.handle(req, next).await.unwrap();
        assert_eq!(analytics.snapshot().requests.total, 0);
    }

    // Regression: `req.path` is the raw target, so a query string used to leak
    // into the endpoint key (`/users/123?ref=x`), defeating normalization and
    // giving an attacker unbounded distinct keys in the capped endpoint table.
    #[tokio::test]
    async fn test_middleware_strips_query_from_endpoint_key() {
        use std::future::Future;
        use std::pin::Pin;

        let analytics = Analytics::new(AnalyticsConfig::default());
        let mw = AnalyticsMiddleware::new(analytics.clone());

        for query in ["?ref=x", "?ref=y", "?ref=z"] {
            let req = HttpRequest::new("GET", format!("/users/123{}", query));
            let next: Next = Box::new(|_req: HttpRequest| {
                Box::pin(async { Ok(HttpResponse::ok()) })
                    as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
            });
            mw.handle(req, next).await.unwrap();
        }

        let snapshot = analytics.snapshot();
        assert_eq!(snapshot.endpoints.len(), 1, "query must not fork the key");
        assert_eq!(snapshot.endpoints[0].path, "/users/:id");
    }

    // The exclusion prefixes are matched against the query-free path, so a
    // query string cannot smuggle an excluded path back into the recording.
    #[tokio::test]
    async fn test_middleware_exclusion_ignores_query() {
        use std::future::Future;
        use std::pin::Pin;

        let analytics = Analytics::new(AnalyticsConfig::default());
        let mw = AnalyticsMiddleware::new(analytics.clone());
        let req = HttpRequest::new("GET", "/health?cache-bust=1".to_string());
        let next: Next = Box::new(|_req: HttpRequest| {
            Box::pin(async { Ok(HttpResponse::ok()) })
                as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        });
        mw.handle(req, next).await.unwrap();
        assert_eq!(analytics.snapshot().requests.total, 0);
    }

    // With `include_query_params`, the query is appended exactly once on top of
    // the query-free normalized path — not doubled.
    #[tokio::test]
    async fn test_middleware_include_query_params_appends_once() {
        use std::future::Future;
        use std::pin::Pin;

        let analytics = Analytics::new(
            AnalyticsConfig::builder()
                .include_query_params(true)
                .build(),
        );
        let mw = AnalyticsMiddleware::new(analytics.clone());
        let req = HttpRequest::new("GET", "/users/123?b=2&a=1".to_string());
        let next: Next = Box::new(|_req: HttpRequest| {
            Box::pin(async { Ok(HttpResponse::ok()) })
                as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        });
        mw.handle(req, next).await.unwrap();

        let snapshot = analytics.snapshot();
        assert_eq!(snapshot.endpoints.len(), 1);
        assert_eq!(snapshot.endpoints[0].path, "/users/:id?a&b");
    }

    // Query values carry tokens and personal data: only names are tracked,
    // even under the verbose development preset.
    #[tokio::test]
    async fn test_development_preset_records_query_keys_only() {
        use std::future::Future;
        use std::pin::Pin;

        let analytics = Analytics::new(AnalyticsConfig::development());
        let mw = AnalyticsMiddleware::new(analytics.clone());
        let req = HttpRequest::new("GET", "/reset?token=s3cr3t&email=a@b.c".to_string());
        let next: Next = Box::new(|_req: HttpRequest| {
            Box::pin(async { Ok(HttpResponse::ok()) })
                as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        });
        mw.handle(req, next).await.unwrap();

        let snapshot = analytics.snapshot();
        assert_eq!(snapshot.endpoints[0].path, "/reset?email&token");
    }

    fn peer_request() -> HttpRequest {
        HttpRequest::new("GET", "/".to_string())
            .with_peer(Some(std::net::SocketAddr::from(([198, 51, 100, 23], 4000))))
    }

    #[test]
    fn test_client_id_ignores_spoofable_headers_by_default() {
        let config = AnalyticsConfig::default();
        let mut req = peer_request();
        req.headers.insert("x-client-id", "victim");
        req.headers.insert("x-forwarded-for", "1.2.3.4");
        req.headers.insert("x-real-ip", "5.6.7.8");
        assert_eq!(
            extract_client_id(&req, &config),
            Some("198.51.100.0/24".to_string())
        );
    }

    #[test]
    fn test_client_id_uses_rightmost_trusted_hop() {
        let config = AnalyticsConfig::builder().trusted_proxy_depth(1).build();
        let mut req = peer_request();
        req.headers
            .insert("x-forwarded-for", "1.2.3.4, 203.0.113.9");
        assert_eq!(
            extract_client_id(&req, &config),
            Some("203.0.113.0/24".to_string())
        );
    }

    #[test]
    fn test_client_id_header_only_when_configured() {
        let config = AnalyticsConfig::builder()
            .client_id_header("x-gateway-client")
            .build();
        let mut req = peer_request();
        req.headers.insert("x-gateway-client", "tenant-42");
        assert_eq!(
            extract_client_id(&req, &config),
            Some("tenant-42".to_string())
        );
    }

    #[test]
    fn test_client_ip_anonymization() {
        assert_eq!(anonymize_ip("10.1.2.3".parse().unwrap()), "10.1.2.0/24");
        assert_eq!(
            anonymize_ip("2001:db8:1:2:3:4:5:6".parse().unwrap()),
            "2001:db8:1::/48"
        );
        assert_eq!(
            anonymize_ip("::ffff:10.1.2.3".parse().unwrap()),
            "10.1.2.0/24"
        );
        assert_eq!(anonymize_client_id("user-7"), "user-7");

        let config = AnalyticsConfig::builder()
            .anonymize_client_ips(false)
            .build();
        assert_eq!(
            extract_client_id(&peer_request(), &config),
            Some("198.51.100.23".to_string())
        );
    }
}
