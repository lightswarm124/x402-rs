//! Unified Paygate implementation supporting both V1 and V2 x402 protocols.
//!
//! This module provides a trait-based abstraction that allows sharing the core
//! payment gate logic between protocol versions while allowing version-specific
//! behavior through the [`PaygateProtocol`] trait.
//!
//! ## Overview
//!
//! The paygate handles:
//! - Extracting payment headers from requests
//! - Verifying payments with the facilitator
//! - Settling payments on-chain
//! - Returning appropriate 402 responses when payment is required
//!
//! ## Example
//!
//! ```ignore
//! use x402_axum::paygate::{Paygate, PaygateProtocol};
//!
//! // Create a paygate for V1 or V2 protocol
//! let paygate = Paygate {
//!     facilitator,
//!     settle_before_execution: false,
//!     accepts: Arc::new(price_tags),
//!     resource: ResourceInfoBuilder::default().as_resource_info(&base_url, &uri),
//! };
//!
//! // Handle a request
//! let response = paygate.handle_request(inner, request).await;
//! ```

use axum_core::body::Body;
use axum_core::extract::Request;
use axum_core::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, Uri};
use serde_json::json;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tower::Service;
use url::Url;
use x402_types::facilitator::Facilitator;
use x402_types::proto;
use x402_types::proto::{SupportedResponse, v1, v2};

#[cfg(feature = "telemetry")]
use tracing::Instrument;
#[cfg(feature = "telemetry")]
use tracing::instrument;
use x402_types::proto::v2::ExtensionsJson;
use x402_types::util::Base64Bytes;

// ============================================================================
// Common Types
// ============================================================================

/// Builder for resource information that can be used with both V1 and V2 protocols.
#[derive(Debug, Clone, Default)]
pub struct ResourceInfoBuilder {
    /// Description of the protected resource
    pub description: Option<String>,
    /// MIME type of the protected resource
    pub mime_type: Option<String>,
    /// Optional explicit URL of the protected resource
    pub url: Option<String>,
}

impl ResourceInfoBuilder {
    /// Determines the resource URL (static or dynamic).
    ///
    /// If `url` is set, returns it directly. Otherwise, constructs a URL by combining
    /// the base URL with the request URI's path and query.
    pub fn as_resource_info(&self, base_url: Option<&Url>, req: &Request) -> v2::ResourceInfo {
        let url = self.url.clone().unwrap_or_else(|| {
            let mut url = base_url.cloned().unwrap_or_else(|| {
                let host = req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or("localhost");
                let origin = format!("http://{}", host);
                let url = Url::parse(&origin).unwrap_or_else(|_| Url::parse("http://localhost").unwrap());
                #[cfg(feature = "telemetry")]
                tracing::warn!(
                    "X402Middleware base_url is not configured; using {url} as origin for resource resolution"
                );
                url
            });
            let request_uri = req.uri();
            url.set_path(request_uri.path());
            url.set_query(request_uri.query());
            url.to_string()
        });
        v2::ResourceInfo {
            description: self.description.clone(),
            mime_type: self.mime_type.clone(),
            url,
        }
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Common verification errors shared between protocol versions.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("{0} header is required")]
    PaymentHeaderRequired(&'static str),
    #[error("Invalid or malformed payment header")]
    InvalidPaymentHeader,
    #[error("Unable to find matching payment requirements")]
    NoPaymentMatching,
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Precondition failed: {0}")]
    PreconditionFailed(String),
}

/// Paygate error type that wraps verification and settlement errors.
#[derive(Debug, thiserror::Error)]
pub enum PaygateError {
    #[error(transparent)]
    Verification(#[from] VerificationError),
    #[error("Settlement failed: {0}")]
    Settlement(String),
}

// ============================================================================
// PaygateProtocol Trait
// ============================================================================

/// Trait defining version-specific behavior for the x402 payment gate.
///
/// This trait is implemented directly on the price tag types (`V1PriceTag` and
/// `V2PriceTag`/`v2::PaymentRequirements`), allowing the core payment gate logic
/// to be shared while version-specific behavior is implemented separately.
pub trait PaygateProtocol: Clone + Send + Sync + 'static {
    /// The payment payload type extracted from the request header.
    type PaymentPayload: serde::de::DeserializeOwned + Send;

    /// The HTTP header name for the payment payload.
    const PAYMENT_HEADER_NAME: &'static str;

    /// Constructs a verify request from the payment payload and accepted requirements.
    ///
    /// The `resource` parameter provides resource information that may be needed
    /// for protocol-specific requirements (e.g., V1 includes resource info in PaymentRequirements).
    fn make_verify_request(
        payload: Self::PaymentPayload,
        accepts: &[Self],
        resource: &v2::ResourceInfo,
    ) -> Result<proto::VerifyRequest, VerificationError>;

    /// Converts an error into an HTTP response with appropriate format.
    fn error_into_response(
        err: PaygateError,
        accepts: &[Self],
        resource: &v2::ResourceInfo,
        extensions: &ExtensionsJson,
    ) -> Response;

    /// Converts the verify response to the protocol-specific format and validates it.
    fn validate_verify_response(
        verify_response: proto::VerifyResponse,
    ) -> Result<(), VerificationError>;

    /// Enriches a price tag with facilitator capabilities.
    ///
    /// Called by middleware when building 402 response to add extra information like fee payer
    /// from the facilitator's supported endpoints.
    fn enrich_with_capabilities(&mut self, capabilities: &SupportedResponse);

    /// Whether this offered price must settle before the protected handler runs.
    fn settles_upfront(&self) -> bool {
        false
    }

    /// Whether the requirements accepted by this payload settle before execution.
    fn selected_settles_upfront(_payload: &Self::PaymentPayload, _accepts: &[Self]) -> bool {
        false
    }
}

// ============================================================================
// V1 Protocol Implementation (on v1::PriceTag)
// ============================================================================

impl PaygateProtocol for v1::PriceTag {
    type PaymentPayload = v1::PaymentPayload;

    const PAYMENT_HEADER_NAME: &'static str = "X-PAYMENT";

    fn make_verify_request(
        payment_payload: Self::PaymentPayload,
        accepts: &[Self],
        resource: &v2::ResourceInfo,
    ) -> Result<proto::VerifyRequest, VerificationError> {
        let selected = accepts
            .iter()
            .find(|requirement| {
                requirement.scheme == payment_payload.scheme
                    && requirement.network == payment_payload.network
            })
            .ok_or(VerificationError::NoPaymentMatching)?;

        let verify_request = v1::VerifyRequest {
            x402_version: v1::X402Version1,
            payment_payload,
            payment_requirements: price_tag_to_v1_requirements_with_resource(selected, resource),
        };

        verify_request
            .try_into()
            .map_err(|e| VerificationError::VerificationFailed(format!("{e}")))
    }

    fn error_into_response(
        err: PaygateError,
        accepts: &[Self],
        resource: &v2::ResourceInfo,
        _extensions: &ExtensionsJson,
    ) -> Response {
        match err {
            PaygateError::Verification(err) => {
                let payment_required_response = v1::PaymentRequired {
                    error: Some(err.to_string()),
                    accepts: accepts
                        .iter()
                        .map(|pt| price_tag_to_v1_requirements_with_resource(pt, resource))
                        .collect(),
                    x402_version: v1::X402Version1,
                };
                let payment_required_response_bytes =
                    serde_json::to_vec(&payment_required_response).expect("serialization failed");
                let body = Body::from(payment_required_response_bytes);
                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .expect("Fail to construct response")
            }
            PaygateError::Settlement(err) => {
                let body = Body::from(
                    json!({
                        "error": "Settlement failed",
                        "details": err.to_string()
                    })
                    .to_string(),
                );
                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .expect("Fail to construct response")
            }
        }
    }

    fn validate_verify_response(
        verify_response: proto::VerifyResponse,
    ) -> Result<(), VerificationError> {
        let verify_response_v1: v1::VerifyResponse = verify_response
            .try_into()
            .map_err(|e| VerificationError::VerificationFailed(format!("{e}")))?;

        match verify_response_v1 {
            v1::VerifyResponse::Valid { .. } => Ok(()),
            v1::VerifyResponse::Invalid { reason, .. } => {
                Err(VerificationError::VerificationFailed(reason))
            }
        }
    }

    fn enrich_with_capabilities(&mut self, capabilities: &SupportedResponse) {
        self.enrich(capabilities);
    }
}

/// Helper function to convert V1PriceTag to v1::PaymentRequirements with resource info.
fn price_tag_to_v1_requirements_with_resource(
    price_tag: &v1::PriceTag,
    resource: &v2::ResourceInfo,
) -> v1::PaymentRequirements {
    v1::PaymentRequirements {
        scheme: price_tag.scheme.clone(),
        network: price_tag.network.clone(),
        max_amount_required: price_tag.amount.clone(),
        resource: resource.url.clone(),
        description: resource.description.clone().unwrap_or_default(),
        mime_type: resource.mime_type.clone(),
        output_schema: None,
        pay_to: price_tag.pay_to.clone(),
        max_timeout_seconds: price_tag.max_timeout_seconds,
        asset: price_tag.asset.clone(),
        extra: price_tag.extra.clone(),
    }
}

// ============================================================================
// V2 Protocol Implementation (on v2::PaymentRequirements / V2PriceTag)
// ============================================================================

impl PaygateProtocol for v2::PriceTag {
    type PaymentPayload = v2::PaymentPayload<v2::PaymentRequirements, serde_json::Value>;

    const PAYMENT_HEADER_NAME: &'static str = "Payment-Signature";

    fn settles_upfront(&self) -> bool {
        self.requirements
            .extra
            .as_ref()
            .and_then(|extra| extra.get("paymentFlow"))
            .and_then(|flow| flow.as_str())
            == Some("upfront")
    }

    fn selected_settles_upfront(payload: &Self::PaymentPayload, accepts: &[Self]) -> bool {
        accepts
            .iter()
            .any(|price_tag| *price_tag == payload.accepted && price_tag.settles_upfront())
    }

    fn make_verify_request(
        mut payment_payload: Self::PaymentPayload,
        accepts: &[Self],
        resource: &v2::ResourceInfo,
    ) -> Result<proto::VerifyRequest, VerificationError> {
        // In V2, the accepted requirements are embedded in the payload.
        // Upfront schemes bind settlement to the server resource, not the client copy.
        let selected = accepts
            .iter()
            .find(|price_tag| **price_tag == payment_payload.accepted)
            .ok_or(VerificationError::NoPaymentMatching)?;
        if selected.settles_upfront() {
            payment_payload.resource = Some(resource.clone());
        }

        // Build the V2 verify request
        let verify_request = v2::VerifyRequest {
            x402_version: v2::X402Version2,
            payment_payload,
            payment_requirements: selected.requirements.clone(),
        };

        let raw = serde_json::to_value(&verify_request)
            .and_then(|json_string| serde_json::value::to_raw_value(&json_string))
            .map_err(|e| VerificationError::VerificationFailed(format!("{e}")))?;

        Ok(proto::VerifyRequest::from(raw))
    }

    fn error_into_response(
        err: PaygateError,
        accepts: &[Self],
        resource: &v2::ResourceInfo,
        extensions: &ExtensionsJson,
    ) -> Response {
        match err {
            PaygateError::Verification(err) => {
                let status_code = if let VerificationError::PreconditionFailed(_) = &err {
                    StatusCode::PRECONDITION_FAILED
                } else {
                    StatusCode::PAYMENT_REQUIRED
                };
                let payment_required_response = v2::PaymentRequired {
                    error: Some(err.to_string()),
                    accepts: accepts.iter().map(|pt| pt.requirements.clone()).collect(),
                    x402_version: v2::X402Version2,
                    resource: Some(resource.clone()),
                    extensions: extensions.clone(),
                };
                // V2 sends payment required in the "Payment-Required" header (base64 encoded)
                let payment_required_bytes =
                    serde_json::to_vec(&payment_required_response).expect("serialization failed");
                let payment_required_header = Base64Bytes::encode(&payment_required_bytes);
                let header_value = HeaderValue::from_bytes(payment_required_header.as_ref())
                    .expect("Failed to create header value");

                Response::builder()
                    .status(status_code)
                    .header("Payment-Required", header_value)
                    .body(Body::empty())
                    .expect("Fail to construct response")
            }
            PaygateError::Settlement(err) => {
                let body = Body::from(
                    json!({
                        "error": "Settlement failed",
                        "details": err.to_string()
                    })
                    .to_string(),
                );
                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .expect("Fail to construct response")
            }
        }
    }

    fn validate_verify_response(
        verify_response: proto::VerifyResponse,
    ) -> Result<(), VerificationError> {
        let verify_response_v2: v2::VerifyResponse = verify_response
            .try_into()
            .map_err(|e| VerificationError::VerificationFailed(format!("{e}")))?;

        match verify_response_v2 {
            v2::VerifyResponse::Valid { .. } => Ok(()),
            v2::VerifyResponse::Invalid { reason, payer: _ } => {
                if reason == "permit2_allowance_required" {
                    Err(VerificationError::PreconditionFailed(reason))
                } else {
                    Err(VerificationError::VerificationFailed(reason))
                }
            }
        }
    }

    fn enrich_with_capabilities(&mut self, capabilities: &SupportedResponse) {
        self.enrich(capabilities);
    }
}

// ============================================================================
// Unified Paygate Implementation
// ============================================================================

/// Unified payment gate that works with both V1 and V2 protocols.
///
/// The protocol version is determined by the price tag type parameter `P`, which must
/// implement [`PaygateProtocol`]. Use `V1PriceTag` for V1 protocol or `V2PriceTag`
/// (alias for `v2::PaymentRequirements`) for V2 protocol.
pub struct Paygate<TPriceTag, TFacilitator> {
    /// The facilitator for verifying and settling payments
    pub facilitator: TFacilitator,
    /// Whether to settle before or after request execution
    pub settle_before_execution: bool,
    /// Accepted payment requirements
    pub accepts: Arc<Vec<TPriceTag>>,
    /// Resource information for the protected endpoint
    pub resource: v2::ResourceInfo,
    /// Protocol extensions declared by the protected endpoint
    pub extensions: Arc<ExtensionsJson>,
}

impl<TPriceTag, TFacilitator> Paygate<TPriceTag, TFacilitator> {
    /// Calls the inner service with proper telemetry instrumentation.
    async fn call_inner<
        ReqBody,
        ResBody,
        S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>>,
    >(
        mut inner: S,
        req: http::Request<ReqBody>,
    ) -> Result<http::Response<ResBody>, S::Error>
    where
        S::Future: Send,
    {
        #[cfg(feature = "telemetry")]
        {
            inner
                .call(req)
                .instrument(tracing::info_span!("inner"))
                .await
        }
        #[cfg(not(feature = "telemetry"))]
        {
            inner.call(req).await
        }
    }
}

impl<TPriceTag, TFacilitator> Paygate<TPriceTag, TFacilitator>
where
    TPriceTag: PaygateProtocol,
    TFacilitator: Facilitator,
{
    /// Handles an incoming request, processing payment if required.
    ///
    /// Returns 402 response if payment fails.
    /// Otherwise, returns the response from the inner service.
    #[cfg_attr(
        feature = "telemetry",
        instrument(name = "x402.handle_request", skip_all)
    )]
    pub async fn handle_request<
        ReqBody,
        ResBody,
        S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>>,
    >(
        self,
        inner: S,
        req: http::Request<ReqBody>,
    ) -> Result<Response, Infallible>
    where
        S::Response: IntoResponse,
        S::Error: IntoResponse,
        S::Future: Send,
    {
        match self.handle_request_fallible(inner, req).await {
            Ok(response) => Ok(response),
            Err(err) => {
                // Get enriched accepts for 402 response
                Ok(TPriceTag::error_into_response(
                    err,
                    &self.accepts,
                    &self.resource,
                    &self.extensions,
                ))
            }
        }
    }

    /// Gets enriched price tags with facilitator capabilities.
    pub async fn enrich_accepts(&mut self) {
        // Try to get capabilities, use empty if fails
        let capabilities = self.facilitator.supported().await.unwrap_or_default();

        let accepts = self
            .accepts
            .iter()
            .map(|pt| {
                let mut pt_clone = pt.clone();
                pt_clone.enrich_with_capabilities(&capabilities);
                pt_clone
            })
            .collect::<Vec<_>>();
        self.accepts = Arc::new(accepts);
    }

    /// Handles an incoming request, returning errors as `PaygateError`.
    ///
    /// This is the fallible version of `handle_request` that returns an actual error
    /// instead of turning it into 402 Payment Required response.
    pub async fn handle_request_fallible<
        ReqBody,
        ResBody,
        S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>>,
    >(
        &self,
        inner: S,
        req: http::Request<ReqBody>,
    ) -> Result<Response, PaygateError>
    where
        S::Response: IntoResponse,
        S::Error: IntoResponse,
        S::Future: Send,
    {
        // Extract payment payload from headers
        let header = extract_payment_header(req.headers(), TPriceTag::PAYMENT_HEADER_NAME).ok_or(
            VerificationError::PaymentHeaderRequired(TPriceTag::PAYMENT_HEADER_NAME),
        )?;
        let payment_payload = extract_payment_payload::<TPriceTag::PaymentPayload>(header)
            .ok_or(VerificationError::InvalidPaymentHeader)?;

        let settle_first = self.settle_before_execution
            || TPriceTag::selected_settles_upfront(&payment_payload, &self.accepts);
        let verify_request =
            TPriceTag::make_verify_request(payment_payload, &self.accepts, &self.resource)?;

        if settle_first {
            // Settlement before execution: settle payment first, then call inner handler
            #[cfg(feature = "telemetry")]
            tracing::debug!("Settling payment before request execution");

            let settlement = self.settle_payment(&verify_request).await?;
            validate_settlement(&settlement)?;

            let header_value = settlement_to_header(settlement.clone())?;

            // Settlement succeeded, add it as an extension and execute the request
            let (mut parts, body) = req.into_parts();
            parts.extensions.insert(Some(settlement));
            let req = Request::from_parts(parts, body);

            let response = match Self::call_inner(inner, req).await {
                Ok(response) => response,
                Err(err) => return Ok(err.into_response()),
            };

            // Add payment response header
            let mut res = response;
            res.headers_mut().insert("Payment-Response", header_value);
            Ok(res.into_response())
        } else {
            // Settlement after execution (default): call inner handler first, then settle
            #[cfg(feature = "telemetry")]
            tracing::debug!("Settling payment after request execution");

            let verify_response = self.verify_payment(&verify_request).await?;

            TPriceTag::validate_verify_response(verify_response)?;

            // Add None to extensions since we haven't settled yet
            let (mut parts, body) = req.into_parts();
            parts.extensions.insert(None::<proto::SettleResponse>);
            let req = Request::from_parts(parts, body);

            let response = match Self::call_inner(inner, req).await {
                Ok(response) => response,
                Err(err) => return Ok(err.into_response()),
            };

            if response.status().is_client_error() || response.status().is_server_error() {
                return Ok(response.into_response());
            }

            let settlement = self.settle_payment(&verify_request).await?;
            validate_settlement(&settlement)?;

            let header_value = settlement_to_header(settlement)?;

            let mut res = response;
            res.headers_mut().insert("Payment-Response", header_value);
            Ok(res.into_response())
        }
    }

    /// Verifies a payment with the facilitator.
    pub async fn verify_payment(
        &self,
        verify_request: &proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, VerificationError> {
        let verify_response = self
            .facilitator
            .verify(verify_request)
            .await
            .map_err(|e| VerificationError::VerificationFailed(format!("{e}")))?;
        Ok(verify_response)
    }

    /// Settles a payment with the facilitator.
    pub async fn settle_payment(
        &self,
        settle_request: &proto::SettleRequest,
    ) -> Result<proto::SettleResponse, PaygateError> {
        let settle_response = self
            .facilitator
            .settle(settle_request)
            .await
            .map_err(|e| PaygateError::Settlement(format!("{e}")))?;
        Ok(settle_response)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extracts the payment header value from the header map.
fn extract_payment_header<'a>(header_map: &'a HeaderMap, header_name: &'a str) -> Option<&'a [u8]> {
    header_map.get(header_name).map(|h| h.as_bytes())
}

/// Extracts and deserializes the payment payload from base64-encoded header bytes.
fn extract_payment_payload<T>(header_bytes: &[u8]) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    let base64 = Base64Bytes::from(header_bytes).decode().ok()?;
    let value = serde_json::from_slice(base64.as_ref()).ok()?;
    Some(value)
}

/// Validates that a [`proto::SettleResponse`] indicates successful settlement.
///
/// The facilitator may return HTTP 200 with `{ "success": false }` when on-chain
/// settlement fails (e.g., insufficient funds, reverted transaction). Without this
/// check, the paygate would serve the protected resource despite failed payment.
///
/// # Fail-safe behavior
///
/// - `success: true` → Ok
/// - `success: false` → Error with `errorReason` extracted if available
/// - `success` missing or non-boolean → Error (non-compliant facilitator response)
///
/// See: <https://github.com/x402-rs/x402-rs/issues/65>
fn validate_settlement(settlement: &proto::SettleResponse) -> Result<(), PaygateError> {
    match settlement.0.get("success").and_then(|v| v.as_bool()) {
        Some(true) => Ok(()),
        Some(false) => {
            let reason = settlement
                .0
                .get("errorReason")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Err(PaygateError::Settlement(format!(
                "facilitator returned success: false (reason: {reason})"
            )))
        }
        None => Err(PaygateError::Settlement(
            "settlement response missing boolean 'success' field".into(),
        )),
    }
}

/// Converts a [`proto::SettleResponse`] into an HTTP header value.
///
/// Returns an error response if conversion fails.
fn settlement_to_header(settlement: proto::SettleResponse) -> Result<HeaderValue, PaygateError> {
    let json =
        serde_json::to_vec(&settlement).map_err(|err| PaygateError::Settlement(err.to_string()))?;
    let payment_header = Base64Bytes::encode(json);
    HeaderValue::from_bytes(payment_header.as_ref())
        .map_err(|err| PaygateError::Settlement(err.to_string()))
}

// ============================================================================
// PriceTagSource Trait and Implementations
// ============================================================================

/// Trait for types that can provide price tags for a request.
///
/// This trait abstracts over static and dynamic pricing strategies.
/// Implementations must be infallible - they always return price tags.
///
/// # Example
///
/// ```ignore
/// use x402_axum::paygate::{PriceTagSource, StaticPriceTags, DynamicPriceTags};
///
/// // Static pricing - same price for every request
/// let static_source = StaticPriceTags::new(vec![my_price_tag]);
///
/// // Dynamic pricing - compute price per-request
/// let dynamic_source = DynamicPriceTags::new(|headers, uri, base_url| async move {
///     vec![compute_price_tag(headers)]
/// });
/// ```
pub trait PriceTagSource {
    /// The concrete price tag type produced by this source.
    type PriceTag: PaygateProtocol;

    /// Resolves price tags for the given request context.
    ///
    /// This method is infallible - it must always return a non-empty vector of price tags.
    fn resolve(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
        base_url: Option<&Url>,
    ) -> impl Future<Output = Vec<Self::PriceTag>> + Send;
}

// ============================================================================
// StaticPriceTags Implementation
// ============================================================================

/// Static price tag source - returns the same price tags for every request.
///
/// This is the default implementation used when calling `with_price_tag()`.
/// It simply stores a vector of price tags and returns clones on each request.
///
/// # Example
///
/// ```ignore
/// use x402_axum::paygate::StaticPriceTags;
///
/// let source = StaticPriceTags::new(vec![V1Eip155Exact::price_tag(pay_to, amount)]);
/// ```
#[derive(Clone, Debug)]
pub struct StaticPriceTags<TPriceTag> {
    tags: Arc<Vec<TPriceTag>>,
}

impl<TPriceTag> StaticPriceTags<TPriceTag> {
    /// Creates a new static price tag source from a vector of price tags.
    pub fn new(tags: Vec<TPriceTag>) -> Self {
        Self {
            tags: Arc::new(tags),
        }
    }

    /// Returns a reference to the stored price tags.
    pub fn tags(&self) -> &[TPriceTag] {
        &self.tags
    }
}

impl<TPriceTag> StaticPriceTags<TPriceTag>
where
    TPriceTag: Clone,
{
    /// Adds a price tag to the source.
    pub fn with_price_tag(mut self, tag: TPriceTag) -> Self {
        let mut tags = (*self.tags).clone();
        tags.push(tag);
        self.tags = Arc::new(tags);
        self
    }
}

impl<TPriceTag> PriceTagSource for StaticPriceTags<TPriceTag>
where
    TPriceTag: PaygateProtocol,
{
    type PriceTag = TPriceTag;

    async fn resolve(
        &self,
        _headers: &HeaderMap,
        _uri: &Uri,
        _base_url: Option<&Url>,
    ) -> Vec<Self::PriceTag> {
        // Simply clone the static tags
        (*self.tags).clone()
    }
}

// ============================================================================
// DynamicPriceTags Implementation
// ============================================================================

/// Internal type alias for the boxed dynamic pricing callback.
/// Users don't interact with this directly.
///
/// Uses higher-ranked trait bounds (HRTB) to express that the callback
/// works with any lifetime of the input references.
type BoxedDynamicPriceCallback<TPriceTag> = dyn for<'a> Fn(
        &'a HeaderMap,
        &'a Uri,
        Option<&'a Url>,
    ) -> Pin<Box<dyn Future<Output = Vec<TPriceTag>> + Send + 'a>>
    + Send
    + Sync;

/// Dynamic price tag source - computes price tags per-request via callback.
///
/// This implementation allows computing different prices based on request
/// headers, URI, or other runtime factors.
///
/// # Example
///
/// ```ignore
/// use alloy_primitives::address;
/// use x402_axum::paygate::DynamicPriceTags;
/// use x402_chain_eip155::V1Eip155Exact;
/// use x402_types::networks::USDC;
///
/// // Users write a simple async closure - no Box::pin needed!
/// let source = DynamicPriceTags::new(|headers, uri, _base_url| async move {
///     let is_premium = headers
///         .get("X-User-Tier")
///         .and_then(|v| v.to_str().ok())
///         .map(|v| v == "premium")
///         .unwrap_or(false);
///
///     let amount = if is_premium { "0.005" } else { "0.01" };
///     vec![V1Eip155Exact::price_tag(
///         address!("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
///         USDC::base_sepolia().parse(amount).unwrap()
///     )]
/// });
/// ```
pub struct DynamicPriceTags<TPriceTag> {
    callback: Arc<BoxedDynamicPriceCallback<TPriceTag>>,
}

impl<TPriceTag> Clone for DynamicPriceTags<TPriceTag> {
    fn clone(&self) -> Self {
        Self {
            callback: self.callback.clone(),
        }
    }
}

impl<TPriceTag> std::fmt::Debug for DynamicPriceTags<TPriceTag> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicPriceTags")
            .field("callback", &"<callback>")
            .finish()
    }
}

impl<TPriceTag> DynamicPriceTags<TPriceTag> {
    /// Creates a new dynamic price source from an async closure.
    ///
    /// The closure receives request context and returns a vector of price tags.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alloy_primitives::address;
    /// use x402_chain_eip155::V1Eip155Exact;
    /// use x402_types::networks::USDC;
    ///
    /// DynamicPriceTags::new(|_headers, _uri, _base_url| async move {
    ///     vec![V1Eip155Exact::price_tag(
    ///         address!("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
    ///         USDC::base_sepolia().parse("0.01").unwrap()
    ///     )]
    /// })
    /// ```
    pub fn new<F, Fut>(callback: F) -> Self
    where
        F: Fn(&HeaderMap, &Uri, Option<&Url>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Vec<TPriceTag>> + Send + 'static,
    {
        Self {
            callback: Arc::new(move |headers, uri, base_url| {
                Box::pin(callback(headers, uri, base_url))
            }),
        }
    }
}

impl<TPriceTag> PriceTagSource for DynamicPriceTags<TPriceTag>
where
    TPriceTag: PaygateProtocol,
{
    type PriceTag = TPriceTag;

    async fn resolve(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
        base_url: Option<&Url>,
    ) -> Vec<Self::PriceTag> {
        (self.callback)(headers, uri, base_url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn settle_response(value: serde_json::Value) -> proto::SettleResponse {
        proto::SettleResponse(value)
    }

    #[test]
    fn validate_settlement_success_true() {
        let resp = settle_response(json!({ "success": true, "txHash": "0xabc" }));
        assert!(validate_settlement(&resp).is_ok());
    }

    #[test]
    fn validate_settlement_success_false_with_reason() {
        let resp = settle_response(json!({
            "success": false,
            "errorReason": "insufficient_funds"
        }));
        let err = validate_settlement(&resp).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("success: false"), "got: {msg}");
        assert!(msg.contains("insufficient_funds"), "got: {msg}");
    }

    #[test]
    fn validate_settlement_success_false_no_reason() {
        let resp = settle_response(json!({ "success": false }));
        let err = validate_settlement(&resp).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn validate_settlement_missing_success_field() {
        let resp = settle_response(json!({ "txHash": "0xabc" }));
        let err = validate_settlement(&resp).unwrap_err();
        assert!(err.to_string().contains("missing boolean"));
    }

    #[test]
    fn validate_settlement_success_is_string() {
        let resp = settle_response(json!({ "success": "true" }));
        let err = validate_settlement(&resp).unwrap_err();
        assert!(err.to_string().contains("missing boolean"));
    }

    #[test]
    fn validate_settlement_success_is_number() {
        let resp = settle_response(json!({ "success": 1 }));
        let err = validate_settlement(&resp).unwrap_err();
        assert!(err.to_string().contains("missing boolean"));
    }

    #[test]
    fn validate_settlement_empty_object() {
        let resp = settle_response(json!({}));
        let err = validate_settlement(&resp).unwrap_err();
        assert!(err.to_string().contains("missing boolean"));
    }

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use x402_types::facilitator::Facilitator;
    use x402_types::util::Base64Bytes;

    #[derive(Clone, Copy)]
    enum ScriptedMode {
        Success,
        Pending,
        Claim,
    }

    #[derive(Clone)]
    struct Scripted {
        events: Arc<Mutex<Vec<String>>>,
        urls: Arc<Mutex<Vec<String>>>,
        claims: Arc<Mutex<HashMap<String, String>>>,
        mode: ScriptedMode,
    }

    impl Scripted {
        fn new(mode: ScriptedMode) -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                urls: Arc::new(Mutex::new(Vec::new())),
                claims: Arc::new(Mutex::new(HashMap::new())),
                mode,
            }
        }
    }

    impl Facilitator for Scripted {
        type Error = String;

        fn verify(
            &self,
            _request: &proto::VerifyRequest,
        ) -> impl Future<Output = Result<proto::VerifyResponse, Self::Error>> + Send {
            self.events.lock().unwrap().push("verify".to_string());
            async { Ok(v1::VerifyResponse::valid("payer".to_string()).into()) }
        }

        fn settle(
            &self,
            request: &proto::SettleRequest,
        ) -> impl Future<Output = Result<proto::SettleResponse, Self::Error>> + Send {
            self.events.lock().unwrap().push("settle".to_string());
            let body = request.as_str().to_string();
            let mode = self.mode;
            let urls = self.urls.clone();
            let claims = self.claims.clone();
            async move {
                let json: serde_json::Value =
                    serde_json::from_str(&body).map_err(|e| e.to_string())?;
                let url = json
                    .pointer("/paymentPayload/resource/url")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .to_string();
                let tx = json
                    .pointer("/paymentPayload/payload/transaction")
                    .and_then(|value| value.as_str())
                    .unwrap_or("tx")
                    .to_string();
                urls.lock().unwrap().push(url.clone());
                match mode {
                    ScriptedMode::Pending => Ok(proto::SettleResponse(json!({
                        "success": false,
                        "errorReason": "settlement_pending"
                    }))),
                    ScriptedMode::Success => Ok(proto::SettleResponse(json!({
                        "success": true,
                        "payer": "payer",
                        "transaction": tx,
                        "network": "bch:bitcoincash"
                    }))),
                    ScriptedMode::Claim => {
                        let mut claims = claims.lock().unwrap();
                        match claims.get(&tx) {
                            Some(existing) if existing == &url => {
                                Ok(proto::SettleResponse(json!({
                                    "success": true,
                                    "payer": "payer",
                                    "transaction": tx,
                                    "network": "bch:bitcoincash"
                                })))
                            }
                            Some(_) => {
                                Err("transaction already claimed for another request".to_string())
                            }
                            None => {
                                claims.insert(tx.clone(), url);
                                Ok(proto::SettleResponse(json!({
                                    "success": true,
                                    "payer": "payer",
                                    "transaction": tx,
                                    "network": "bch:bitcoincash"
                                })))
                            }
                        }
                    }
                }
            }
        }

        async fn supported(&self) -> Result<proto::SupportedResponse, Self::Error> {
            Ok(proto::SupportedResponse::default())
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn price(flow: Option<&str>) -> v2::PriceTag {
        let mut extra = json!({"assetTransferMethod": "native"});
        if let Some(flow) = flow {
            extra["paymentFlow"] = json!(flow);
        }
        v2::PriceTag {
            requirements: v2::PaymentRequirements {
                scheme: "exact".to_string(),
                network: "bch:bitcoincash".parse().unwrap(),
                amount: "1000".to_string(),
                pay_to: "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue".to_string(),
                max_timeout_seconds: 300,
                asset: "BCH".to_string(),
                extra: Some(extra),
            },
            enricher: None,
        }
    }

    fn payment_header(requirements: &v2::PaymentRequirements, resource: &str) -> String {
        let payload = v2::PaymentPayload {
            accepted: requirements.clone(),
            payload: json!({"transaction": "same-tx"}),
            resource: Some(v2::ResourceInfo {
                url: resource.to_string(),
                description: None,
                mime_type: None,
            }),
            x402_version: v2::X402Version2,
            extensions: ExtensionsJson::default(),
        };
        Base64Bytes::encode(serde_json::to_vec(&payload).unwrap()).to_string()
    }

    fn paid_request(header: &str) -> Request {
        let mut request = Request::builder().uri("/paid").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert("Payment-Signature", HeaderValue::from_str(header).unwrap());
        request
    }

    fn counting_handler(
        calls: Arc<AtomicUsize>,
        events: Arc<Mutex<Vec<String>>>,
    ) -> impl tower::Service<
        Request,
        Response = Response,
        Error = Infallible,
        Future = impl Future<Output = Result<Response, Infallible>> + Send,
    > {
        tower::service_fn(move |_request: Request| {
            let calls = calls.clone();
            let events = events.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                events.lock().unwrap().push("handler".to_string());
                Ok(Response::new(Body::from("paid")))
            }
        })
    }

    fn gate(scripted: Scripted, tag: v2::PriceTag, url: &str) -> Paygate<v2::PriceTag, Scripted> {
        Paygate {
            facilitator: scripted,
            settle_before_execution: false,
            accepts: Arc::new(vec![tag]),
            resource: v2::ResourceInfo {
                url: url.to_string(),
                description: None,
                mime_type: None,
            },
            extensions: Arc::new(ExtensionsJson::default()),
        }
    }

    #[test]
    fn upfront_pending_settlement_does_not_run_handler() {
        let scripted = Scripted::new(ScriptedMode::Pending);
        let tag = price(Some("upfront"));
        let header = payment_header(&tag.requirements, "https://attacker.example/paid");
        let calls = Arc::new(AtomicUsize::new(0));
        let response = runtime()
            .block_on(
                gate(scripted.clone(), tag, "https://merchant.example/item").handle_request(
                    counting_handler(calls.clone(), scripted.events.clone()),
                    paid_request(&header),
                ),
            )
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            scripted.events.lock().unwrap().as_slice(),
            ["settle".to_string()]
        );
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[test]
    fn upfront_success_runs_handler_only_after_settlement() {
        let scripted = Scripted::new(ScriptedMode::Success);
        let tag = price(Some("upfront"));
        let header = payment_header(&tag.requirements, "https://attacker.example/paid");
        let calls = Arc::new(AtomicUsize::new(0));
        let response = runtime()
            .block_on(
                gate(scripted.clone(), tag, "https://merchant.example/item").handle_request(
                    counting_handler(calls.clone(), scripted.events.clone()),
                    paid_request(&header),
                ),
            )
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            scripted.events.lock().unwrap().as_slice(),
            ["settle".to_string(), "handler".to_string()]
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            scripted.urls.lock().unwrap().as_slice(),
            ["https://merchant.example/item".to_string()]
        );
    }

    #[test]
    fn non_upfront_still_runs_handler_before_failed_settlement() {
        let scripted = Scripted::new(ScriptedMode::Pending);
        let tag = price(None);
        let header = payment_header(&tag.requirements, "https://client.example/resource");
        let calls = Arc::new(AtomicUsize::new(0));
        let response = runtime()
            .block_on(
                gate(scripted.clone(), tag, "https://merchant.example/item").handle_request(
                    counting_handler(calls.clone(), scripted.events.clone()),
                    paid_request(&header),
                ),
            )
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            scripted.events.lock().unwrap().as_slice(),
            [
                "verify".to_string(),
                "handler".to_string(),
                "settle".to_string()
            ]
        );
        assert_eq!(
            scripted.urls.lock().unwrap().as_slice(),
            ["https://client.example/resource".to_string()]
        );
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[test]
    fn upfront_cross_resource_replay_does_not_run_second_handler() {
        let scripted = Scripted::new(ScriptedMode::Claim);
        let tag = price(Some("upfront"));
        let header = payment_header(&tag.requirements, "https://attacker.example/paid");
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let runtime = runtime();
        let first = runtime
            .block_on(
                gate(
                    scripted.clone(),
                    tag.clone(),
                    "https://merchant.example/one",
                )
                .handle_request(
                    counting_handler(first_calls.clone(), scripted.events.clone()),
                    paid_request(&header),
                ),
            )
            .unwrap();
        let second = runtime
            .block_on(
                gate(scripted.clone(), tag, "https://merchant.example/two").handle_request(
                    counting_handler(second_calls.clone(), scripted.events.clone()),
                    paid_request(&header),
                ),
            )
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(second_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            scripted.urls.lock().unwrap().as_slice(),
            [
                "https://merchant.example/one".to_string(),
                "https://merchant.example/two".to_string()
            ]
        );
    }

    #[test]
    fn upfront_same_resource_retry_is_idempotent() {
        let scripted = Scripted::new(ScriptedMode::Claim);
        let tag = price(Some("upfront"));
        let header = payment_header(&tag.requirements, "https://attacker.example/paid");
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = runtime();
        let first = runtime
            .block_on(
                gate(
                    scripted.clone(),
                    tag.clone(),
                    "https://merchant.example/item",
                )
                .handle_request(
                    counting_handler(calls.clone(), scripted.events.clone()),
                    paid_request(&header),
                ),
            )
            .unwrap();
        let second = runtime
            .block_on(
                gate(scripted.clone(), tag, "https://merchant.example/item").handle_request(
                    counting_handler(calls.clone(), scripted.events.clone()),
                    paid_request(&header),
                ),
            )
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            scripted.urls.lock().unwrap().as_slice(),
            [
                "https://merchant.example/item".to_string(),
                "https://merchant.example/item".to_string()
            ]
        );
    }
}
