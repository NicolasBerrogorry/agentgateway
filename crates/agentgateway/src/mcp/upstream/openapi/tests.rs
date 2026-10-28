use std::borrow::Cow;
use std::sync::Arc;

use agent_core::{metrics, strng};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use openapiv3::{OpenAPI, ReferenceOr};
use prometheus_client::registry::Registry;
use rmcp::model::Tool;
use rstest::rstest;
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

use super::*;
use crate::client::Client;
use crate::proxy::httpproxy::PolicyClient;
use crate::serdes::FileInlineOrRemote;
use crate::store::{BackendPolicies, Stores};
use crate::types::agent::{Backend, ResourceName, SimpleBackend, Target};
use crate::types::local::{
	LocalBackend, LocalMcpBackend, LocalMcpTarget, LocalMcpTargetSpec, McpBackendHost,
	McpStatefulMode,
};
use crate::{BackendConfig, ProxyInputs, client, mcp};

// Helper to create a handler and mock server for tests.
// Use prefix "" for no path prefix, or e.g. "/v2" for a path prefix.
fn route(name: &str, location: ParameterLocation, required: bool) -> ParameterRoute {
	ParameterRoute {
		name: name.to_string(),
		location,
		key: name.to_string(),
		required,
	}
}

async fn setup_with_prefix(prefix: &str) -> (MockServer, Handler) {
	let server = MockServer::start().await;
	let host = server.uri();
	let parsed = reqwest::Url::parse(&host).unwrap();
	let config = crate::config::parse_config("{}".to_string(), None).unwrap();
	let encoder = config.session_encoder.clone();
	let stores = Stores::with_ipv6_enabled(config.ipv6_enabled);
	let client = Client::new(
		&client::Config {
			resolver_cfg: ResolverConfig::default(),
			resolver_opts: ResolverOpts::default(),
		},
		None,
		BackendConfig::default(),
		None,
	);
	let pi = Arc::new(ProxyInputs {
		cfg: Arc::new(config),
		stores: stores.clone(),
		metrics: Arc::new(crate::metrics::Metrics::new(
			metrics::sub_registry(&mut Registry::default()),
			Default::default(),
			Default::default(),
		)),
		model_catalog: crate::llm::catalog::ModelCatalog::empty(),
		admin: None,
		upstream: client.clone(),
		ca: None,
		spiffe: None,

		mcp_state: mcp::router::App::new(stores.clone(), encoder),
		admission: Default::default(),
	});

	let client = PolicyClient::new(pi.clone());
	// Tools carry a FLAT input schema: parameters beside body properties, each routed by
	// the UpstreamOpenAPICall's parameter list.
	let test_tool_get = Tool::new(
		Cow::Borrowed("get_user"),
		Cow::Borrowed("Get user details"),
		Arc::new(
			json!({
				"type": "object",
				"properties": {
					"user_id": {"type": "string"},
					"verbose": {"type": "string"},
					"X-Request-ID": {"type": "string"}
				},
				"required": ["user_id"]
			})
			.as_object()
			.unwrap()
			.clone(),
		),
	);
	let upstream_call_get = UpstreamOpenAPICall {
		method: "GET".to_string(),
		path: "/users/{user_id}".to_string(),
		allowed_headers: HashSet::from(["X-Request-ID".to_string()]),
		content_type: None,
		parameters: vec![
			route("user_id", ParameterLocation::Path, true),
			route("verbose", ParameterLocation::Query, false),
			route("X-Request-ID", ParameterLocation::Header, false),
		],
		request_body: false,
		base_path: None,
	};
	let test_tool_doc = Tool::new(
		Cow::Borrowed("get_doc"),
		Cow::Borrowed("Get an internal document"),
		Arc::new(
			json!({
				"type": "object",
				"properties": {
					"tenant": {"type": "string"},
					"kind": {"type": "string"},
					"id": {"type": "string"}
				},
				"required": ["tenant", "kind", "id"]
			})
			.as_object()
			.unwrap()
			.clone(),
		),
	);
	let upstream_call_doc = UpstreamOpenAPICall {
		method: "GET".to_string(),
		path: "/v1/{tenant}/{kind}/{id}".to_string(),
		allowed_headers: HashSet::new(),
		content_type: None,
		parameters: vec![
			route("tenant", ParameterLocation::Path, true),
			route("kind", ParameterLocation::Path, true),
			route("id", ParameterLocation::Path, true),
		],
		request_body: false,
		base_path: None,
	};

	// The body's own properties sit at the root; the framing headers are DECLARED here so
	// the protected-header rule is what keeps them off the wire, not the schema.
	let test_tool_post = Tool::new(
		Cow::Borrowed("create_user"),
		Cow::Borrowed("Create a new user"),
		Arc::new(
			json!({
				"type": "object",
				"properties": {
					"name": {"type": "string"},
					"email": {"type": "string"},
					"source": {"type": "string"},
					"X-API-Key": {"type": "string"},
					"content-length": {"type": "string"},
					"content-type": {"type": "string"},
					"transfer-encoding": {"type": "string"},
					"host": {"type": "string"}
				},
				"required": ["name", "email"]
			})
			.as_object()
			.unwrap()
			.clone(),
		),
	);
	let upstream_call_post = UpstreamOpenAPICall {
		method: "POST".to_string(),
		path: "/users".to_string(),
		allowed_headers: HashSet::from([
			"X-API-Key".to_string(),
			"content-length".to_string(),
			"content-type".to_string(),
			"transfer-encoding".to_string(),
			"host".to_string(),
		]),
		content_type: None,
		parameters: vec![
			route("source", ParameterLocation::Query, false),
			route("X-API-Key", ParameterLocation::Header, false),
			route("content-length", ParameterLocation::Header, false),
			route("content-type", ParameterLocation::Header, false),
			route("transfer-encoding", ParameterLocation::Header, false),
			route("host", ParameterLocation::Header, false),
		],
		request_body: true,
		base_path: None,
	};

	let backend = SimpleBackend::Opaque(
		ResourceName::new(strng::literal!("dummy"), "".into()),
		Target::Hostname(
			parsed.host().unwrap().to_string().into(),
			parsed.port().unwrap_or(8080),
		),
	);
	let upstream_client = super::super::McpHttpClient::new(
		client,
		backend,
		BackendPolicies::default(),
		false,
		"test-target".to_string(),
	);
	let handler = Handler::new(
		upstream_client,
		vec![
			(test_tool_get, upstream_call_get),
			(test_tool_doc, upstream_call_doc),
			(test_tool_post, upstream_call_post),
		],
		prefix.to_string(),
	);

	(server, handler)
}

async fn setup() -> (MockServer, Handler) {
	setup_with_prefix("").await
}

#[tokio::test]
async fn listen_emits_empty_ack_and_keeps_the_stream_open() {
	use futures_util::StreamExt;
	use rmcp::model::*;

	let (_, handler) = setup().await;
	let request = JsonRpcRequest {
		jsonrpc: JsonRpcVersion2_0,
		id: RequestId::Number(7),
		request: ClientRequest::SubscriptionsListenRequest(SubscriptionsListenRequest::new(
			SubscriptionsListenRequestParams::new(SubscriptionFilter::new()),
		)),
	};
	let mut stream = handler
		.send_message(request, &IncomingRequestContext::empty())
		.await
		.unwrap();
	let first = stream.next().await.unwrap().unwrap();
	assert_eq!(
		serde_json::to_value(first).unwrap(),
		json!({
			"jsonrpc": "2.0",
			"method": "notifications/subscriptions/acknowledged",
			"params": {"notifications": {}}
		})
	);
	assert!(
		tokio::time::timeout(std::time::Duration::from_millis(10), stream.next())
			.await
			.is_err()
	);
}

#[tokio::test]
async fn test_call_tool_full_url_server_prefix() {
	// When OpenAPI spec has servers: [{ url: "https://api.example.com/" }],
	// get_server_prefix returns "" so the request goes to /users/{id} (no double host).
	let prefix = super::get_server_prefix(&openapi_with_servers(
		json!([{ "url": "https://api.example.com/" }]),
	))
	.expect("should parse");
	assert_eq!(
		prefix, "",
		"full URL with root path should yield empty prefix"
	);

	let (server, handler) = setup_with_prefix(&prefix).await;
	let user_id = "123";
	let expected_response = json!({ "id": user_id, "name": "Test User" });

	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(
		result.is_ok(),
		"full-URL server prefix should not cause invalid authority"
	);
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_call_tool_path_prefix_server() {
	// When OpenAPI spec has servers: [{ url: "https://api.example.com/v2" }],
	// get_server_prefix returns "/v2" and requests go to /v2/users/{id}.
	let prefix = super::get_server_prefix(&openapi_with_servers(
		json!([{ "url": "https://api.example.com/v2" }]),
	))
	.expect("should parse");
	assert_eq!(prefix, "/v2", "full URL with path should yield path prefix");

	let (server, handler) = setup_with_prefix(&prefix).await;
	let user_id = "456";
	let expected_response = json!({ "id": user_id, "name": "Versioned User" });

	Mock::given(method("GET"))
		.and(path(format!("/v2/users/{user_id}")))
		.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_call_tool_get_simple_success() {
	let (server, handler) = setup().await;

	let user_id = "123";
	let expected_response = json!({ "id": user_id, "name": "Test User" });

	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_call_tool_get_with_query() {
	let (server, handler) = setup().await;

	let user_id = "456";
	let verbose_flag = "true";
	let expected_response =
		json!({ "id": user_id, "name": "Test User", "details": "Verbose details" });

	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.and(query_param("verbose", verbose_flag))
		.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id, "verbose": verbose_flag });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_call_tool_get_with_header() {
	let (server, handler) = setup().await;

	let user_id = "789";
	let request_id = "req-abc";
	let expected_response = json!({ "id": user_id, "name": "Another User" });

	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.and(header("X-Request-ID", request_id))
		.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id, "X-Request-ID": request_id });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_call_tool_post_with_body() {
	let (server, handler) = setup().await;

	let request_body = json!({ "name": "New User", "email": "new@example.com" });
	let expected_response = json!({ "id": "xyz", "name": "New User", "email": "new@example.com" });

	Mock::given(method("POST"))
		.and(path("/users"))
		.and(body_json(&request_body))
		.respond_with(ResponseTemplate::new(201).set_body_json(&expected_response))
		.mount(&server)
		.await;

	let args = request_body.clone();
	let result = handler
		.call_tool(
			"create_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_call_tool_post_all_params() {
	let (server, handler) = setup().await;

	let request_body = json!({ "name": "Complete User", "email": "complete@example.com" });
	let api_key = "secret-key";
	let source = "test-suite";
	let expected_response = json!({ "id": "comp-123", "name": "Complete User" });

	Mock::given(method("POST"))
		.and(path("/users"))
		.and(query_param("source", source))
		.and(header("X-API-Key", api_key))
		.and(body_json(&request_body))
		.respond_with(ResponseTemplate::new(201).set_body_json(&expected_response))
		.mount(&server)
		.await;

	let args = json!({
			"name": "Complete User",
			"email": "complete@example.com",
			"source": source,
			"X-API-Key": api_key
	});
	let result = handler
		.call_tool(
			"create_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_call_tool_tool_not_found() {
	let (_server, handler) = setup().await; // Mock server not needed

	let args = json!({});
	let result = handler
		.call_tool(
			"nonexistent_tool",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_err());
	assert!(
		result
			.unwrap_err()
			.to_string()
			.contains("tool nonexistent_tool not found")
	);
}

#[tokio::test]
async fn test_call_tool_upstream_error() {
	let (server, handler) = setup().await;

	let user_id = "error-user";
	let error_response = json!({ "error": "User not found" });

	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.respond_with(ResponseTemplate::new(404).set_body_json(&error_response))
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok());
	let result = result.unwrap();
	// A client error is the model's to act on: the body comes back, marked as an error.
	assert_eq!(result.is_error, Some(true));
	assert_eq!(result.structured_content.unwrap(), error_response);
}

#[tokio::test]
async fn test_call_tool_upstream_internal_error() {
	let (server, handler) = setup().await;

	let user_id = "error-user";
	let error_response = json!({ "error": "Something went wrong accessing Github :unicorn:" });

	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.respond_with(ResponseTemplate::new(500).set_body_json(&error_response))
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_err());
	let err = result.unwrap_err();
	assert!(
		err
			.to_string()
			.contains("failed with status 500 Internal Server Error"),
		"error was {}",
		err
	);
	assert!(err.to_string().contains(&error_response.to_string()));
}

#[tokio::test]
async fn test_call_tool_invalid_header_value() {
	let (server, handler) = setup().await;

	let user_id = "header-issue";
	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": user_id })))
		.mount(&server)
		.await;

	// Intentionally provide a non-string header value
	let args = json!({ "user_id": user_id, "X-Request-ID": 12345 });

	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;
	assert!(result.is_ok());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		json!({ "id": user_id })
	);
}

#[tokio::test]
async fn test_call_tool_invalid_query_param_value() {
	let (server, handler) = setup().await;

	let user_id = "query-issue";
	// Mock is set up but won't be hit with the invalid query param
	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		// IMPORTANT: We don't .and(query_param(...)) here because the invalid param is skipped
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": user_id })))
		.mount(&server)
		.await;

	// Intentionally provide a non-string query value
	let args = json!({ "user_id": user_id, "verbose": true });

	// We expect the call to succeed, but the invalid query param should be skipped (and logged)
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;
	assert!(result.is_ok());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		json!({ "id": user_id })
	);
}

#[tokio::test]
async fn test_call_tool_invalid_path_param_value() {
	let (server, handler) = setup().await;
	let args = json!({ "user_id": true });

	let error = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await
		.unwrap_err();

	assert!(matches!(error, UpstreamError::InvalidRequest(_)));
	assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_call_tool_with_compressed_response() {
	let (server, handler) = setup().await;

	let user_id = "compressed-user";
	let expected_response = json!({ "id": user_id, "name": "Compressed User", "data": "This is a longer response that benefits from compression" });

	// Encode the response body with gzip
	let response_json = serde_json::to_vec(&expected_response).unwrap();
	let compressed_body = crate::http::compression::encode_body(&response_json, "gzip")
		.await
		.unwrap();

	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.respond_with(
			ResponseTemplate::new(200)
				.insert_header("Content-Encoding", "gzip")
				.set_body_bytes(compressed_body),
		)
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_call_tool_response_wrapping() {
	let (server, handler) = setup().await;

	// (wrapped, raw_body_bytes, expected_parsed_value)
	let test_cases: &[(bool, &[u8], Value)] = &[
		(false, b"null", Value::Null),
		(
			false,
			br#"{"id":"123","name":"Test User","email":"test@example.com"}"#,
			json!({ "id": "123", "name": "Test User", "email": "test@example.com" }),
		),
		(
			true,
			br#"[{"id":1,"name":"1"},{"id":2,"name":"2"},{"id":3,"name":"3"}]"#,
			json!([ { "id": 1, "name": "1" }, { "id": 2, "name": "2" }, { "id": 3, "name": "3" }]),
		),
		(
			false,
			b"plain text response",
			json!({"code": 200, "message": "plain text response"}),
		),
		(true, b"42", json!(42)),
		(true, b"true", json!(true)),
	];

	for (i, (wrapped, body, response)) in test_cases.iter().enumerate() {
		let user_id = format!("{}", i);
		Mock::given(method("GET"))
			.and(path(format!("/users/{}", user_id)))
			.respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
			.expect(1)
			.mount(&server)
			.await;

		let args = json!({ "user_id": user_id });
		let result = handler
			.call_tool(
				"get_user",
				Some(args.as_object().unwrap().clone()),
				&IncomingRequestContext::empty(),
			)
			.await;

		assert!(result.is_ok(), "result {:?}", result);

		// Spec requires an object https://modelcontextprotocol.io/specification/2025-06-18/schema#calltoolresult
		let expected = if *wrapped {
			json!({ "data": response })
		} else {
			response.clone()
		};
		assert_eq!(result.unwrap().structured_content.unwrap(), expected);
	}
}

#[tokio::test]
async fn test_call_tool_image_response() {
	let (server, handler) = setup().await;

	// PNG signature followed by bytes that are not valid UTF-8
	let png: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe";

	Mock::given(method("GET"))
		.and(path("/users/img"))
		.respond_with(
			ResponseTemplate::new(200)
				.insert_header("content-type", "image/png; charset=binary")
				.set_body_bytes(png.to_vec()),
		)
		.mount(&server)
		.await;

	let args = json!({ "user_id": "img" });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await
		.unwrap();

	assert!(result.structured_content.is_none());
	assert_eq!(result.content.len(), 1);
	let rmcp::model::ContentBlock::Image(image) = &result.content[0] else {
		panic!("expected image content, got {:?}", result.content[0]);
	};
	use base64::Engine;
	assert_eq!(image.mime_type, "image/png");
	assert_eq!(
		image.data,
		base64::engine::general_purpose::STANDARD.encode(png)
	);
}

#[tokio::test]
async fn test_call_tool_text_response_ignores_content_type() {
	let (server, handler) = setup().await;

	Mock::given(method("GET"))
		.and(path("/users/txt"))
		.respond_with(
			ResponseTemplate::new(200)
				.insert_header("content-type", "text/plain")
				.set_body_string("plain text response"),
		)
		.mount(&server)
		.await;

	let args = json!({ "user_id": "txt" });
	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await
		.unwrap();

	let expected = json!({"code": 200, "message": "plain text response"});
	assert_eq!(result.structured_content, Some(expected.clone()));
	let rmcp::model::ContentBlock::Text(text) = &result.content[0] else {
		panic!("expected text content, got {:?}", result.content[0]);
	};
	assert_eq!(serde_json::from_str::<Value>(&text.text).unwrap(), expected);
}

#[tokio::test]
async fn test_normalize_url_path_empty_prefix() {
	// Test the fix for double slash issue when prefix is empty (host/port config)
	let result = super::normalize_url_path("", "/mqtt/healthcheck");
	assert_eq!(result, "/mqtt/healthcheck");
}

#[tokio::test]
async fn test_normalize_url_path_with_prefix() {
	// Test with a prefix that has trailing slash
	let result = super::normalize_url_path("/api/v3/", "/pet");
	assert_eq!(result, "/api/v3/pet");
}

#[tokio::test]
async fn test_normalize_url_path_prefix_no_trailing_slash() {
	// Test with a prefix without trailing slash
	let result = super::normalize_url_path("/api/v3", "/pet");
	assert_eq!(result, "/api/v3/pet");
}

#[tokio::test]
async fn test_normalize_url_path_path_without_leading_slash() {
	// Test with path that doesn't start with slash
	let result = super::normalize_url_path("/api/v3", "pet");
	assert_eq!(result, "/api/v3/pet");
}

#[rstest]
#[case::empty_prefix("", "/mqtt/healthcheck", "/mqtt/healthcheck")]
#[case::with_prefix("/api/v3/", "/pet", "/api/v3/pet")]
#[case::prefix_no_trailing_slash("/api/v3", "/pet", "/api/v3/pet")]
#[case::without_leading_slash("/api/v3", "pet", "/api/v3/pet")]
#[case::empty_prefix_path_without_slash("", "pet", "/pet")]
fn test_normalize_url_path(#[case] prefix: &str, #[case] path: &str, #[case] expected: &str) {
	let result = super::normalize_url_path(prefix, path);
	assert_eq!(result, expected);
}

fn openapi_with_servers(servers: serde_json::Value) -> OpenAPI {
	let spec = json!({
		"openapi": "3.0.0",
		"info": { "title": "Test", "version": "1.0.0" },
		"servers": servers,
		"paths": { "/x": { "get": { "operationId": "getX", "responses": { "200": { "description": "ok" } } } } }
	});
	serde_json::from_value(spec).expect("valid OpenAPI spec")
}

#[rstest]
#[case::full_url_root("https://api.example.com/", "")]
#[case::full_url_no_trailing_slash("https://api.example.com", "")]
#[case::full_url_with_path("https://api.example.com/v2", "/v2")]
#[case::full_url_with_path_trailing_slash("https://api.example.com/v2/", "/v2")]
#[case::full_url_with_host_variable("https://{tenant}.example.com/v1", "/v1")]
#[case::full_url_with_host_variable_no_path("https://{tenant}.example.com", "")]
#[case::full_url_with_host_variable_root("https://{tenant}.example.com/", "")]
#[case::full_url_with_path_variable("https://api.example.com/v1/{version}", "/v1/{version}")]
#[case::relative_path("/api/v1", "/api/v1")]
#[case::empty_string("", "")]
fn test_get_server_prefix(#[case] server_url: &str, #[case] expected: &str) {
	let spec = openapi_with_servers(json!([{ "url": server_url }]));
	let result = super::get_server_prefix(&spec).expect("should succeed");
	assert_eq!(result, expected, "server_url={server_url}");
}

#[tokio::test]
async fn test_get_server_prefix_empty_servers() {
	let spec = openapi_with_servers(json!([]));
	let result = super::get_server_prefix(&spec).expect("should succeed");
	assert_eq!(result, "");
}

#[tokio::test]
async fn test_get_server_prefix_multiple_servers_err() {
	let spec = openapi_with_servers(json!([
		{ "url": "https://api.example.com/" },
		{ "url": "https://api2.example.com/" }
	]));
	let result = super::get_server_prefix(&spec);
	assert!(result.is_err(), "multiple servers should yield error");
}

fn tool_schema_for<'a>(
	tools: &'a [(Tool, UpstreamOpenAPICall)],
	tool_name: &str,
) -> &'a serde_json::Map<String, serde_json::Value> {
	tools
		.iter()
		.find(|(tool, _)| tool.name == tool_name)
		.map(|(tool, _)| &*tool.input_schema)
		.expect("tool should exist")
}

#[test]
fn test_parse_openapi_schema_maps_summary_to_tool_title() {
	let raw = r#"{
		"openapi": "3.0.0",
		"info": {"title": "Titles", "version": "1.0.0"},
		"paths": {
			"/tags": {
				"get": {
					"operationId": "getTagsForWorkspace",
					"summary": "Get tags in a workspace",
					"description": "Returns the tags in a workspace",
					"responses": {"200": {"description": "ok"}}
				}
			},
			"/users": {
				"get": {
					"operationId": "getUsers",
					"description": "Returns the users",
					"responses": {"200": {"description": "ok"}}
				}
			}
		}
	}"#;
	let open_api: OpenAPI = serde_json::from_str(raw).expect("valid OpenAPI schema");
	let tools = super::parse_openapi_schema(&open_api).expect("schema should parse");

	let (with_summary, _) = tools
		.iter()
		.find(|(tool, _)| tool.name == "getTagsForWorkspace")
		.expect("tool should exist");
	assert_eq!(
		with_summary.title.as_deref(),
		Some("Get tags in a workspace")
	);
	assert_eq!(
		with_summary.description.as_deref(),
		Some("Returns the tags in a workspace")
	);

	let (without_summary, _) = tools
		.iter()
		.find(|(tool, _)| tool.name == "getUsers")
		.expect("tool should exist");
	assert_eq!(without_summary.title, None);
}

#[rstest]
#[case::required_true(Some(true))]
#[case::required_omitted(None)]
#[case::required_false(Some(false))]
fn test_parse_openapi_schema_requires_path_item_parameters(#[case] required: Option<bool>) {
	let mut parameter = json!({
		"name": "workspace_gid",
		"in": "path",
		"schema": {"type": "string"}
	});
	if let Some(required) = required {
		parameter
			.as_object_mut()
			.unwrap()
			.insert("required".to_string(), json!(required));
	}
	let open_api: OpenAPI = serde_json::from_value(json!({
		"openapi": "3.0.0",
		"info": {"title": "Path Params", "version": "1.0.0"},
		"paths": {
			"/workspaces/{workspace_gid}/tags": {
				"parameters": [parameter],
				"get": {
					"operationId": "getTagsForWorkspace",
					"summary": "Get tags in a workspace",
					"responses": {
						"200": {"description": "ok"}
					}
				}
			}
		}
	}))
	.expect("parseable OpenAPI schema");
	let tools = super::parse_openapi_schema(&open_api).expect("schema should parse");
	let (_tool, upstream) = tools
		.iter()
		.find(|(tool, _)| tool.name == "getTagsForWorkspace")
		.expect("tool should exist");

	assert_eq!(upstream.path, "/workspaces/{workspace_gid}/tags");

	let schema = tool_schema_for(&tools, "getTagsForWorkspace");
	let properties = schema
		.get("properties")
		.and_then(serde_json::Value::as_object)
		.expect("tool schema should include properties");
	assert!(
		properties.contains_key("workspace_gid"),
		"path-level workspace_gid should be exposed in tool schema"
	);
	let required = schema
		.get("required")
		.and_then(serde_json::Value::as_array)
		.expect("tool schema should include required array");
	assert!(
		required.iter().any(|value| value == "workspace_gid"),
		"a path parameter is required whatever the document says"
	);
	assert_eq!(
		upstream.parameters,
		vec![ParameterRoute {
			name: "workspace_gid".into(),
			location: ParameterLocation::Path,
			key: "workspace_gid".into(),
			required: true,
		}]
	);
}

#[test]
fn test_parse_openapi_schema_operation_level_parameter_overrides_path_level_parameter() {
	let raw = r#"{
		"openapi": "3.0.0",
		"info": {"title": "Path Params", "version": "1.0.0"},
		"paths": {
			"/workspaces/{workspace_gid}/tags/{tag_gid}": {
				"parameters": [
					{
						"name": "workspace_gid",
						"in": "path",
						"required": true,
						"description": "path-level parameter",
						"schema": {"type": "string"}
					},
					{
						"name": "tag_gid",
						"in": "path",
						"required": true,
						"schema": {"type": "string"}
					}
				],
				"get": {
					"operationId": "getWorkspaceTag",
					"parameters": [
						{
							"name": "workspace_gid",
							"in": "path",
							"description": "operation-level parameter",
							"schema": {"type": "string", "pattern": "^ws_"}
						}
					],
					"responses": {
						"200": {"description": "ok"}
					}
				}
			}
		}
	}"#;
	let open_api: OpenAPI = serde_json::from_str(raw).expect("parseable OpenAPI schema");
	let tools = super::parse_openapi_schema(&open_api).expect("schema should parse");

	let schema = tool_schema_for(&tools, "getWorkspaceTag");
	let path_properties = schema
		.get("properties")
		.and_then(serde_json::Value::as_object)
		.expect("tool schema should include properties");
	let workspace_gid = path_properties
		.get("workspace_gid")
		.and_then(serde_json::Value::as_object)
		.expect("workspace_gid property should exist");
	assert_eq!(
		workspace_gid.get("description"),
		Some(&json!("operation-level parameter"))
	);
	assert_eq!(workspace_gid.get("pattern"), Some(&json!("^ws_")));

	let required = schema
		.get("required")
		.and_then(serde_json::Value::as_array)
		.expect("tool schema should include required array");
	assert_eq!(required, &vec![json!("workspace_gid"), json!("tag_gid")]);

	assert!(
		path_properties.contains_key("tag_gid"),
		"the unmodified sibling path parameter should keep its slot"
	);
}

#[test]
fn test_parse_openapi_schema_operation_level_header_override_is_case_insensitive() {
	let raw = r#"{
		"openapi": "3.0.0",
		"info": {"title": "Header Params", "version": "1.0.0"},
		"paths": {
			"/workspaces": {
				"parameters": [
					{
						"name": "X-Request-Id",
						"in": "header",
						"required": true,
						"description": "path-level header",
						"schema": {"type": "string"}
					}
				],
				"get": {
					"operationId": "listWorkspaces",
					"parameters": [
						{
							"name": "x-request-id",
							"in": "header",
							"required": true,
							"description": "operation-level header",
							"schema": {"type": "string", "pattern": "^req_"}
						}
					],
					"responses": {
						"200": {"description": "ok"}
					}
				}
			}
		}
	}"#;
	let open_api: OpenAPI = serde_json::from_str(raw).expect("valid OpenAPI schema");
	let tools = super::parse_openapi_schema(&open_api).expect("schema should parse");
	let (tool, upstream) = tools
		.iter()
		.find(|(tool, _)| tool.name == "listWorkspaces")
		.expect("tool should exist");

	assert_eq!(
		upstream.allowed_headers,
		HashSet::from(["x-request-id".to_string()])
	);

	let schema = &*tool.input_schema;
	let header_properties = schema
		.get("properties")
		.and_then(serde_json::Value::as_object)
		.expect("tool schema should include properties");
	assert_eq!(header_properties.len(), 1);
	let request_id = header_properties
		.get("x-request-id")
		.and_then(serde_json::Value::as_object)
		.expect("operation-level header should win");
	assert_eq!(
		request_id.get("description"),
		Some(&json!("operation-level header"))
	);
	assert_eq!(request_id.get("pattern"), Some(&json!("^req_")));

	let required = schema
		.get("required")
		.and_then(serde_json::Value::as_array)
		.expect("tool schema should include required array");
	assert_eq!(required, &vec![json!("x-request-id")]);
}

#[test]
fn test_parse_openapi_schema_documents_but_never_sends_cookie_parameters() {
	let raw = r#"{
		"openapi": "3.0.0",
		"info": {"title": "Cookie Params", "version": "1.0.0"},
		"paths": {
			"/workspaces/{workspace_gid}/tags": {
				"parameters": [
					{
						"name": "session",
						"in": "cookie",
						"required": false,
						"schema": {"type": "string"}
					},
					{
						"name": "workspace_gid",
						"in": "path",
						"required": true,
						"schema": {"type": "string"}
					}
				],
				"get": {
					"operationId": "getTagsForWorkspace",
					"responses": {
						"200": {"description": "ok"}
					}
				}
			}
		}
	}"#;
	let open_api: OpenAPI = serde_json::from_str(raw).expect("valid OpenAPI schema");
	let tools = super::parse_openapi_schema(&open_api).expect("schema should parse");

	let (_, upstream) = tools
		.iter()
		.find(|(tool, _)| tool.name == "getTagsForWorkspace")
		.expect("tool should exist");
	let schema = tool_schema_for(&tools, "getTagsForWorkspace");
	let properties = schema
		.get("properties")
		.and_then(serde_json::Value::as_object)
		.expect("root schema should include properties");
	// Documented, so a model knows the service takes it; routed as a cookie, which the
	// call never sends rather than guessing it into a Cookie header.
	assert!(properties.contains_key("session"));
	assert!(properties.contains_key("workspace_gid"));
	assert!(
		upstream
			.parameters
			.iter()
			.any(|p| p.name == "session" && p.location == ParameterLocation::Cookie)
	);
}

#[test]
fn test_parse_openapi_schema_bundles_recursive_component_schemas() {
	let raw = r##"{
		"openapi": "3.0.0",
		"info": {"title": "Recursive schemas", "version": "1.0.0"},
		"paths": {
			"/nodes": {
				"post": {
					"operationId": "createNode",
					"parameters": [{
						"name": "root",
						"in": "query",
						"required": true,
						"schema": {"$ref": "#/components/schemas/A"}
					}],
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {"$ref": "#/components/schemas/Node"}
							}
						}
					},
					"responses": {"200": {"description": "ok"}}
				}
			}
		},
		"components": {
			"schemas": {
				"Node": {
					"type": "object",
					"properties": {
						"children": {
							"type": "array",
							"items": {"$ref": "#/components/schemas/Node"}
						}
					}
				},
				"A": {
					"type": "object",
					"properties": {"b": {"$ref": "#/components/schemas/B"}}
				},
				"B": {
					"type": "object",
					"properties": {"a": {"$ref": "#/components/schemas/A"}}
				},
				"Unused": {"type": "string"}
			}
		}
	}"##;
	let open_api: OpenAPI = serde_json::from_str(raw).expect("valid OpenAPI schema");
	let tools = super::parse_openapi_schema(&open_api).expect("recursive schemas should parse");

	// The body's root $ref is inlined (MCP wants a literal object root) and the query
	// parameter sits beside its properties; the closure travels under $defs.
	assert_eq!(
		Value::Object(tool_schema_for(&tools, "createNode").clone()),
		json!({
			"type": "object",
			"required": ["root"],
			"properties": {
				"children": {
					"type": "array",
					"items": {"$ref": "#/$defs/Node"}
				},
				"root": {"$ref": "#/$defs/A"}
			},
			"$defs": {
				"Node": {
					"type": "object",
					"properties": {
						"children": {
							"type": "array",
							"items": {"$ref": "#/$defs/Node"}
						}
					}
				},
				"A": {
					"type": "object",
					"properties": {"b": {"$ref": "#/$defs/B"}}
				},
				"B": {
					"type": "object",
					"properties": {"a": {"$ref": "#/$defs/A"}}
				}
			}
		})
	);
}

#[test]
fn test_parse_openapi_schema_degrades_a_dangling_ref_to_an_empty_schema_with_a_warning() {
	let open_api: OpenAPI = serde_json::from_value(json!({
		"openapi": "3.0.0",
		"info": {"title": "Invalid schema ref", "version": "1.0.0"},
		"paths": {
			"/a": {
				"post": {
					"operationId": "postA",
					"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/A"}}}},
					"responses": {"200": {"description": "ok"}}
				}
			}
		},
		"components": {
			"schemas": {
				"A": {"type": "object", "properties": {"b": {"$ref": "#/components/parameters/not-a-schema"}}}
			}
		}
	}))
	.expect("valid OpenAPI document");

	// A reference the document cannot satisfy costs that one schema, not the target.
	let (tools, warnings) =
		super::parse_openapi_schema_with_warnings(&open_api).expect("the target still loads");
	assert_eq!(
		tool_schema_for(&tools, "postA").get("properties"),
		Some(&json!({"b": {}}))
	);
	assert!(
		warnings
			.iter()
			.any(|w| w == "dangling $ref dropped: #/components/parameters/not-a-schema"),
		"warnings: {warnings:?}"
	);
}

#[rstest]
#[case::empty_string(json!({"verbose": ""}), vec![("verbose", "")])]
#[case::string_value(json!({"verbose": "true"}), vec![("verbose", "true")])]
#[case::boolean_true(json!({"verbose": true}), vec![("verbose", "true")])]
#[case::boolean_false(json!({"verbose": false}), vec![("verbose", "false")])]
#[case::integer_value(json!({"verbose": "123"}), vec![("verbose", "123")])]
#[case::special_chars(json!({"verbose": "hello world"}), vec![("verbose", "hello world")])]
#[case::array_values(json!({"verbose": ["a", "b", "c"]}), vec![("verbose", "a"), ("verbose", "b"), ("verbose", "c")])]
#[case::ampersand_in_value(json!({"verbose": "foo&admin=true"}), vec![("verbose", "foo&admin=true")])]
#[case::equals_in_value(json!({"verbose": "foo=bar"}), vec![("verbose", "foo=bar")])]
#[case::question_mark_in_value(json!({"verbose": "foo?bar"}), vec![("verbose", "foo?bar")])]
#[case::combined_injection(json!({"verbose": "x&evil=1&admin=true"}), vec![("verbose", "x&evil=1&admin=true")])]
#[tokio::test]
async fn test_query_param_types(
	#[case] query_args: serde_json::Value,
	#[case] expected_params: Vec<(&str, &str)>,
) {
	let (server, handler) = setup().await;

	let user_id = "test-user";

	let mut mock = Mock::given(method("GET")).and(path(format!("/users/{user_id}")));
	for (key, value) in &expected_params {
		mock = mock.and(query_param(*key, *value));
	}
	mock
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": user_id })))
		.expect(1)
		.mount(&server)
		.await;

	let mut args = json!({ "user_id": user_id });
	args
		.as_object_mut()
		.unwrap()
		.extend(query_args.as_object().unwrap().clone());

	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok(), "Expected success, got: {:?}", result.err());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		json!({ "id": user_id })
	);
}

#[rstest]
#[case::simple_id("123", "/users/123")]
#[case::numeric_id("456", "/users/456")]
#[case::spaces("user name", "/users/user%20name")]
#[case::unicode("user\u{00e9}", "/users/user%C3%A9")]
#[case::dotted_value("v1.2-file..name", "/users/v1.2-file..name")]
#[case::embedded_slashes("user-1/o/er-1001", "/users/user-1%2Fo%2Fer-1001")]
#[case::encoded_project_path("group/project", "/users/group%2Fproject")]
#[case::query_injection("123?admin=true", "/users/123%3Fadmin%3Dtrue")]
#[case::query_with_ampersand("123?a=1&b=2", "/users/123%3Fa%3D1%26b%3D2")]
#[case::hash_fragment("user#section", "/users/user%23section")]
#[case::ampersand_in_path("user&admin=true", "/users/user%26admin%3Dtrue")]
#[tokio::test]
async fn test_path_param_encoding(#[case] user_id: &str, #[case] expected_path: &str) {
	let (server, handler) = setup().await;

	Mock::given(method("GET"))
		.and(path(expected_path))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": user_id })))
		.expect(1)
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id });

	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok(), "Expected success, got: {:?}", result.err());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		json!({ "id": user_id })
	);
}

#[rstest]
#[case::empty("")]
#[case::dot(".")]
#[case::dot_dot("..")]
#[case::leading_parent("../admin")]
#[case::leading_current("./profile")]
#[case::embedded_parent("user/../admin")]
#[case::repeated_separator("user//../admin")]
#[case::backslash_parent("..\\admin")]
#[case::embedded_backslash_parent("user\\..\\admin")]
fn rejects_unsafe_path_params(#[case] value: &str) {
	let params = json!({ "user_id": value }).as_object().unwrap().clone();
	assert!(substitute_path_params("/users/{user_id}", &params).is_err());
}

#[tokio::test]
async fn rejects_traversal_before_sending() {
	let (server, handler) = setup().await;
	let args = json!({ "user_id": "../admin" });

	let error = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await
		.unwrap_err();

	assert!(matches!(error, UpstreamError::InvalidRequest(_)));
	assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn rejects_segment_injection_before_sending() {
	let (server, handler) = setup().await;
	let args = json!({ "user_id": "123/../admin" });

	let error = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await
		.unwrap_err();

	assert!(matches!(error, UpstreamError::InvalidRequest(_)));
	assert!(server.received_requests().await.unwrap().is_empty());
}

#[rstest]
#[case::missing(json!({}), "path parameter 'user_id' is missing")]
#[case::null(json!({"user_id": null}), "path parameter 'user_id' must be a string or number")]
#[case::boolean(json!({"user_id": true}), "path parameter 'user_id' must be a string or number")]
#[case::array(json!({"user_id": []}), "path parameter 'user_id' must be a string or number")]
#[case::object(json!({"user_id": {}}), "path parameter 'user_id' must be a string or number")]
fn rejects_missing_or_unsupported_path_params(#[case] params: Value, #[case] expected_error: &str) {
	let error = substitute_path_params("/users/{user_id}", params.as_object().unwrap()).unwrap_err();
	assert_eq!(error.to_string(), expected_error);
}

#[test]
fn accepts_numeric_path_params() {
	let params = json!({ "user_id": 123 }).as_object().unwrap().clone();
	assert_eq!(
		substitute_path_params("/users/{user_id}", &params).unwrap(),
		"/users/123"
	);
}

#[tokio::test]
async fn rejects_multi_parameter_dot_segment_traversal_before_sending() {
	let (server, handler) = setup().await;
	let args = json!({ "tenant": "..", "kind": "..", "id": "internal" });

	let error = handler
		.call_tool(
			"get_doc",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await
		.unwrap_err();

	assert!(matches!(error, UpstreamError::InvalidRequest(_)));
	assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_schema_defined_headers_work() {
	let (server, handler) = setup().await;

	let user_id = "custom-header-test";
	let expected_response = json!({ "id": user_id });

	// Only X-Request-ID is defined in the schema for get_user tool
	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.and(header("X-Request-ID", "my-request-123"))
		.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
		.expect(1)
		.mount(&server)
		.await;

	let args = json!({ "user_id": user_id, "X-Request-ID": "my-request-123" });

	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(
		result.is_ok(),
		"Schema-defined headers should work: {:?}",
		result.err()
	);
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

// Custom matcher to verify a header is NOT present
struct HeaderNotPresent {
	header_name: String,
}

impl HeaderNotPresent {
	fn new(header_name: impl Into<String>) -> Self {
		Self {
			header_name: header_name.into(),
		}
	}
}

impl Match for HeaderNotPresent {
	fn matches(&self, request: &Request) -> bool {
		!request.headers.contains_key(self.header_name.as_str())
	}
}

#[tokio::test]
async fn test_blocked_headers_are_ignored() {
	let (server, handler) = setup().await;

	let request_body = json!({ "name": "Test User", "email": "test@example.com" });
	let expected_response = json!({ "id": "new-user", "name": "Test User" });

	Mock::given(method("POST"))
		.and(path("/users"))
		.and(header("content-length", "47")) // length of request_body
		.and(header("content-type", "application/json"))
		.and(HeaderNotPresent::new("transfer-encoding"))
		.and(body_json(&request_body))
		.respond_with(ResponseTemplate::new(201).set_body_json(&expected_response))
		.expect(1)
		.mount(&server)
		.await;

	let args = json!({
		"name": "Test User",
		"email": "test@example.com",
		"content-length": "999999999",
		"content-type": "text/plain",
		"transfer-encoding": "chunked",
		"host": "evil.com"
	});

	let result = handler
		.call_tool(
			"create_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	// The request should succeed with the correct headers (blocked headers ignored)
	assert!(result.is_ok(), "Request should succeed: {:?}", result.err());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_headers_not_in_schema_are_ignored() {
	let (server, handler) = setup().await;

	let user_id = "schema-header-test";
	let expected_response = json!({ "id": user_id });

	// Only expect X-Request-ID (defined in schema), NOT X-Malicious-Header
	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.and(header("X-Request-ID", "valid-request"))
		.and(HeaderNotPresent::new("X-Malicious-Header"))
		.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
		.expect(1)
		.mount(&server)
		.await;

	// An undeclared key is nothing to this body-less operation: it is neither a header nor sent.
	let args = json!({
		"user_id": user_id,
		"X-Request-ID": "valid-request",
		"X-Malicious-Header": "should-be-ignored"
	});

	let result = handler
		.call_tool(
			"get_user",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(
		result.is_ok(),
		"Request should succeed with schema-defined headers: {:?}",
		result.err()
	);
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

#[tokio::test]
async fn test_call_tool_structured_content_fallback() {
	// Test that CallToolResult has both content and structured_content populated
	// This verifies our backwards compatibility fix for langchain-mcp-adapter
	let (server, handler) = setup().await;

	let user_id = "test123";
	let expected_response = json!({ "id": user_id, "name": "Test User", "status": "active" });

	Mock::given(method("GET"))
		.and(path(format!("/users/{user_id}")))
		.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
		.mount(&server)
		.await;

	// Test the MCP message handling directly
	use rmcp::model::*;

	let request = JsonRpcRequest {
		jsonrpc: JsonRpcVersion2_0,
		id: RequestId::String("test-123".into()),
		request: ClientRequest::CallToolRequest(CallToolRequest::new(
			CallToolRequestParams::new("get_user")
				.with_arguments(json!({ "user_id": user_id }).as_object().unwrap().clone()),
		)),
	};

	let result = handler
		.send_message(request, &IncomingRequestContext::empty())
		.await;
	assert!(result.is_ok(), "send_message should succeed");

	let messages = result.unwrap();

	// Convert Messages to Vec to inspect CallToolResult
	use futures_util::StreamExt;
	let mut message_stream = messages;
	let message_result = message_stream
		.next()
		.await
		.expect("Should receive at least one message");

	// Handle the Result<JsonRpcMessage, ClientError> wrapper
	let server_msg = message_result.expect("Message processing should succeed");

	let JsonRpcMessage::Response(response) = server_msg else {
		panic!("Should receive a Response message, got: {:?}", server_msg);
	};

	let ServerResult::CallToolResult(call_result) = &response.result else {
		panic!(
			"Response should contain CallToolResult, got: {:?}",
			response.result
		);
	};

	// Test 1: content field should NOT be empty (our backwards compatibility fix)
	assert!(
		!call_result.content.is_empty(),
		"content field should not be empty after our fix"
	);
	assert_eq!(
		call_result.content.len(),
		1,
		"content should have exactly one item"
	);

	// Test 2: structured_content should contain the original JSON
	assert!(
		call_result.structured_content.is_some(),
		"structured_content should be populated"
	);
	let structured_content = call_result.structured_content.as_ref().unwrap();
	assert_eq!(
		*structured_content, expected_response,
		"structured_content should contain original API response"
	);

	// Test 3: content[0] should contain serialized JSON as text
	let content_item = call_result
		.content
		.first()
		.expect("content should have at least one item");

	let rmcp::model::ContentBlock::Text(text_content) = content_item else {
		panic!(
			"content[0] should be Text content type, got: {:?}",
			content_item
		);
	};

	let serialized_json = &text_content.text;
	let parsed_from_content: serde_json::Value =
		serde_json::from_str(serialized_json).expect("content should contain valid JSON string");
	assert_eq!(
		parsed_from_content, expected_response,
		"content should contain serialized version of API response"
	);

	// Test 4: Both fields should represent the same data
	assert_eq!(
		parsed_from_content, *structured_content,
		"content and structured_content should represent the same data"
	);
}

#[tokio::test]
async fn test_openapi_from_url() {
	// Test creating LocalMcpTargetSpec::OpenAPI with URL schema and converting to runtime backend
	let server = MockServer::start().await;

	// Mock OpenAPI schema response
	let openapi_json = json!({
		"openapi": "3.0.0",
		"info": {
			"title": "User API",
			"version": "1.0.0"
		},
		"paths": {
			"/users/{user_id}": {
				"get": {
					"summary": "Get user details",
					"parameters": [
						{
							"name": "user_id",
							"in": "path",
							"required": true,
							"schema": {
								"type": "string"
							}
						}
					],
					"responses": {
						"200": {
							"description": "User details",
							"content": {
								"application/json": {
									"schema": {
										"type": "object",
										"properties": {
											"id": {"type": "string"},
											"name": {"type": "string"}
										}
									}
								}
							}
						}
					}
				}
			},
			"/users": {
				"post": {
					"summary": "Create a new user",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"name": {"type": "string"},
										"email": {"type": "string"}
									},
									"required": ["name", "email"]
								}
							}
						}
					},
					"responses": {
						"201": {
							"description": "User created",
							"content": {
								"application/json": {
									"schema": {
										"type": "object",
										"properties": {
											"id": {"type": "string"},
											"name": {"type": "string"},
											"email": {"type": "string"}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	});

	Mock::given(method("GET"))
		.and(path("/openapi.json"))
		.respond_with(ResponseTemplate::new(200).set_body_json(&openapi_json))
		.mount(&server)
		.await;

	// Create client
	let client = Client::new(
		&client::Config {
			resolver_cfg: ResolverConfig::default(),
			resolver_opts: ResolverOpts::default(),
		},
		None,
		BackendConfig::default(),
		None,
	);

	// Create LocalMcpTargetSpec::OpenAPI with remote URL schema
	let schema_url = format!("{}/openapi.json", server.uri());

	// Use serde_json to create McpBackendHost since fields are private
	let backend_json = json!({
		"host": "https://api.users.com"
	});
	let backend: McpBackendHost = serde_json::from_value(backend_json).unwrap();

	let local_target_spec = LocalMcpTargetSpec::OpenAPI {
		backend,
		schema: FileInlineOrRemote::Remote {
			url: schema_url.parse().unwrap(),
		},
	};

	// Create a LocalBackend::MCP to test the full conversion pipeline
	let local_backend = LocalBackend::MCP(LocalMcpBackend {
		targets: vec![Arc::new(LocalMcpTarget {
			name: "users-api".into(),
			condition: None,
			spec: local_target_spec,
			policies: None,
		})],
		stateful_mode: McpStatefulMode::Stateful,
		prefix_mode: None,
		failure_mode: None,
		sse_keep_alive: None,
		dns_rebinding_protection: false,
		server: None,
	});

	// Convert to runtime backends
	let backend_name = ResourceName::new("test-users".into(), "".into());
	let resources = crate::resource_manager::ResourceFetcher::direct(client);
	let result = local_backend
		.as_backends(
			backend_name,
			&resources,
			crate::mcp::DEFAULT_SESSION_IDLE_TTL,
		)
		.await;

	// Verify the conversion succeeded
	assert!(
		result.is_ok(),
		"Should successfully convert LocalBackend::MCP with remote OpenAPI schema"
	);
	let backends = result.unwrap();

	// Should have at least one backend
	assert!(!backends.is_empty(), "Should have at least one backend");

	// Find the MCP backend
	let mcp_backend = backends
		.iter()
		.find(|b| matches!(b.backend, Backend::MCP(_, _)));
	assert!(mcp_backend.is_some(), "Should contain an MCP backend");

	if let Some(backend_with_policies) = mcp_backend
		&& let Backend::MCP(_, mcp_backend) = &backend_with_policies.backend
	{
		assert_eq!(mcp_backend.targets.len(), 1);

		// Verify the target was converted to OpenAPI
		let target = &mcp_backend.targets[0];
		assert_eq!(target.name.as_str(), "users-api");

		// Verify it's an OpenAPI target spec with the fetched schema
		if let crate::types::agent::McpTargetSpec::OpenAPI(openapi_target) = &target.spec {
			let schema = &openapi_target.schema;
			assert_eq!(schema.openapi, "3.0.0");
			assert_eq!(schema.info.title, "User API");
			assert_eq!(schema.info.version, "1.0.0");

			// Check if paths contains the expected paths
			let has_users_path = schema.paths.paths.contains_key("/users");
			assert!(has_users_path, "Schema should contain /users path");

			let has_users_id_path = schema.paths.paths.contains_key("/users/{user_id}");
			assert!(
				has_users_id_path,
				"Schema should contain /users/{{user_id}} path"
			);

			// Verify the path details were preserved
			if let Some(path_item_ref) = schema.paths.paths.get("/users/{user_id}") {
				match path_item_ref {
					ReferenceOr::Item(path_item) => {
						if let Some(get_op) = &path_item.get {
							assert_eq!(get_op.summary.as_deref(), Some("Get user details"));
						}
					},
					ReferenceOr::Reference { reference: _ } => {
						panic!("Expected path item, got reference");
					},
				}
			}

			if let Some(path_item_ref) = schema.paths.paths.get("/users") {
				match path_item_ref {
					ReferenceOr::Item(path_item) => {
						if let Some(post_op) = &path_item.post {
							assert_eq!(post_op.summary.as_deref(), Some("Create a new user"));
						}
					},
					ReferenceOr::Reference { reference: _ } => {
						panic!("Expected path item, got reference");
					},
				}
			}
		} else {
			panic!("Expected OpenAPI target spec, got {:?}", target.spec);
		}
	}
}

#[test]
fn test_parse_openapi_schema_octet_stream_body() {
	let raw = r#"{
		"openapi": "3.0.0",
		"info": {"title": "Binary Upload", "version": "1.0.0"},
		"paths": {
			"/upload": {
				"post": {
					"operationId": "uploadFile",
					"requestBody": {
						"required": true,
						"content": {
							"application/octet-stream": {
								"schema": {"type": "string", "format": "binary"}
							}
						}
					},
					"responses": {
						"200": {"description": "ok"}
					}
				}
			}
		}
	}"#;
	let open_api: OpenAPI = serde_json::from_str(raw).expect("valid OpenAPI schema");
	let tools = super::parse_openapi_schema(&open_api).expect("schema should parse");

	let (tool, upstream) = tools
		.iter()
		.find(|(tool, _)| tool.name == "uploadFile")
		.expect("tool should exist");

	assert_eq!(
		upstream.content_type.as_deref(),
		Some("application/octet-stream")
	);

	let schema = &*tool.input_schema;
	let properties = schema
		.get("properties")
		.and_then(serde_json::Value::as_object)
		.expect("root schema should include properties");
	assert!(
		properties.contains_key("body"),
		"body property should exist"
	);

	let body_schema = properties
		.get("body")
		.and_then(serde_json::Value::as_object)
		.expect("body should be an object");
	assert_eq!(body_schema.get("type"), Some(&json!("string")));
	assert_eq!(body_schema.get("format"), Some(&json!("byte")));

	let required = schema
		.get("required")
		.and_then(serde_json::Value::as_array)
		.expect("root schema should include required array");
	assert!(
		required.iter().any(|v| v == "body"),
		"body should be required"
	);
}

#[test]
fn test_parse_openapi_schema_json_preferred_over_octet_stream() {
	let raw = r#"{
		"openapi": "3.0.0",
		"info": {"title": "Multi Content", "version": "1.0.0"},
		"paths": {
			"/data": {
				"post": {
					"operationId": "postData",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"name": {"type": "string"}
									}
								}
							},
							"application/octet-stream": {
								"schema": {"type": "string", "format": "binary"}
							}
						}
					},
					"responses": {
						"200": {"description": "ok"}
					}
				}
			}
		}
	}"#;
	let open_api: OpenAPI = serde_json::from_str(raw).expect("valid OpenAPI schema");
	let tools = super::parse_openapi_schema(&open_api).expect("schema should parse");

	let (_tool, upstream) = tools
		.iter()
		.find(|(tool, _)| tool.name == "postData")
		.expect("tool should exist");

	assert_eq!(
		upstream.content_type, None,
		"JSON path should be taken, no special content_type"
	);
}

#[test]
fn test_parse_openapi_schema_unsupported_content_type_no_body_param() {
	let raw = r#"{
		"openapi": "3.0.0",
		"info": {"title": "XML Only", "version": "1.0.0"},
		"paths": {
			"/xml": {
				"post": {
					"operationId": "postXml",
					"requestBody": {
						"required": true,
						"content": {
							"text/xml": {
								"schema": {"type": "string"}
							}
						}
					},
					"responses": {
						"200": {"description": "ok"}
					}
				}
			}
		}
	}"#;
	let open_api: OpenAPI = serde_json::from_str(raw).expect("valid OpenAPI schema");
	let tools = super::parse_openapi_schema(&open_api).expect("schema should parse");

	let (tool, _upstream) = tools
		.iter()
		.find(|(tool, _)| tool.name == "postXml")
		.expect("tool should exist");

	let schema = &*tool.input_schema;
	let properties = schema
		.get("properties")
		.and_then(serde_json::Value::as_object);
	let has_body = properties.is_some_and(|p| p.contains_key("body"));
	assert!(
		!has_body,
		"unsupported content type should not produce a body parameter"
	);
}

struct BinaryBodyMatcher {
	expected_bytes: Vec<u8>,
}

impl Match for BinaryBodyMatcher {
	fn matches(&self, request: &Request) -> bool {
		request.body == self.expected_bytes
	}
}

#[tokio::test]
async fn test_call_tool_with_binary_body() {
	let server = MockServer::start().await;
	let host = server.uri();
	let parsed = reqwest::Url::parse(&host).unwrap();
	let config = crate::config::parse_config("{}".to_string(), None).unwrap();
	let encoder = config.session_encoder.clone();
	let stores = Stores::with_ipv6_enabled(config.ipv6_enabled);
	let client = Client::new(
		&client::Config {
			resolver_cfg: hickory_resolver::config::ResolverConfig::default(),
			resolver_opts: hickory_resolver::config::ResolverOpts::default(),
		},
		None,
		BackendConfig::default(),
		None,
	);
	let pi = Arc::new(ProxyInputs {
		cfg: Arc::new(config),
		stores: stores.clone(),
		metrics: Arc::new(crate::metrics::Metrics::new(
			agent_core::metrics::sub_registry(&mut prometheus_client::registry::Registry::default()),
			Default::default(),
			Default::default(),
		)),
		model_catalog: crate::llm::catalog::ModelCatalog::empty(),
		admin: None,
		upstream: client.clone(),
		ca: None,
		spiffe: None,
		mcp_state: mcp::router::App::new(stores.clone(), encoder),
		admission: Default::default(),
	});

	let client = PolicyClient::new(pi.clone());

	let test_tool_upload = Tool::new(
		Cow::Borrowed("upload_file"),
		Cow::Borrowed("Upload a binary file"),
		Arc::new(
			json!({
				"type": "object",
				"properties": {
					"body": {
						"type": "string",
						"format": "byte",
						"description": "Base64-encoded binary content"
					}
				},
				"required": ["body"]
			})
			.as_object()
			.unwrap()
			.clone(),
		),
	);
	let upstream_call_upload = UpstreamOpenAPICall {
		method: "POST".to_string(),
		path: "/upload".to_string(),
		allowed_headers: HashSet::new(),
		content_type: Some("application/octet-stream".to_string()),
		..Default::default()
	};

	let backend = SimpleBackend::Opaque(
		ResourceName::new(strng::literal!("dummy"), "".into()),
		Target::Hostname(
			parsed.host().unwrap().to_string().into(),
			parsed.port().unwrap_or(8080),
		),
	);
	let upstream_client = super::super::McpHttpClient::new(
		client,
		backend,
		BackendPolicies::default(),
		false,
		"test-target".to_string(),
	);
	let handler = Handler::new(
		upstream_client,
		vec![(test_tool_upload, upstream_call_upload)],
		"".to_string(),
	);

	let binary_data: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
	use base64::Engine;
	let encoded = base64::engine::general_purpose::STANDARD.encode(&binary_data);
	let expected_response = json!({ "status": "uploaded" });

	Mock::given(method("POST"))
		.and(path("/upload"))
		.and(header("content-type", "application/octet-stream"))
		.and(BinaryBodyMatcher {
			expected_bytes: binary_data,
		})
		.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
		.mount(&server)
		.await;

	let args = json!({ "body": encoded });
	let result = handler
		.call_tool(
			"upload_file",
			Some(args.as_object().unwrap().clone()),
			&IncomingRequestContext::empty(),
		)
		.await;

	assert!(result.is_ok(), "Expected success, got: {:?}", result.err());
	assert_eq!(
		result.unwrap().structured_content.unwrap(),
		expected_response
	);
}

// ── The reader's fidelity: what the document says reaches the model ─────────────────────

fn doc(paths: Value) -> OpenAPI {
	doc_with(json!({}), paths)
}

fn doc_with(extra: Value, paths: Value) -> OpenAPI {
	let mut document = json!({
		"openapi": "3.1.0",
		"info": {"title": "Fixture", "version": "1"},
		"paths": paths
	});
	for (k, v) in extra.as_object().unwrap() {
		document[k] = v.clone();
	}
	serde_json::from_value(document).expect("a valid document")
}

fn only_tool(open_api: &OpenAPI) -> (Tool, UpstreamOpenAPICall, Vec<String>) {
	let (mut tools, warnings) = super::parse_openapi_schema_with_warnings(open_api).expect("parses");
	assert_eq!(
		tools.len(),
		1,
		"one operation expected, got {:?}",
		tools
			.iter()
			.map(|t| t.0.name.to_string())
			.collect::<Vec<_>>()
	);
	let (tool, upstream) = tools.pop().unwrap();
	(tool, upstream, warnings)
}

fn post_body(schema: Value) -> Value {
	json!({
		"/things": {
			"post": {
				"operationId": "makeThing",
				"requestBody": {"content": {"application/json": {"schema": schema}}},
				"responses": {}
			}
		}
	})
}

#[test]
fn flat_input_merges_parameters_beside_the_body_and_prefixes_a_collision() {
	let (tool, upstream, _) = only_tool(&doc(json!({
		"/jobs/{id}/logs": {
			"parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
			"post": {
				"operationId": "readLogs",
				"parameters": [
					{"name": "since", "in": "query", "schema": {"type": "string"}},
					{"name": "X-Trace", "in": "header", "schema": {"type": "string"}},
					{"name": "format", "in": "query", "required": true, "schema": {"type": "string"}}
				],
				"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"format": {"type": "string"}}}}}},
				"responses": {}
			}
		}
	})));
	let mut keys: Vec<_> = tool.input_schema["properties"]
		.as_object()
		.unwrap()
		.keys()
		.cloned()
		.collect();
	keys.sort();
	assert_eq!(keys, ["X-Trace", "format", "id", "query_format", "since"]);
	assert_eq!(tool.input_schema["required"], json!(["id", "query_format"]));
	assert!(upstream.request_body);
	assert_eq!(
		upstream.parameters,
		vec![
			route("id", ParameterLocation::Path, true),
			route("since", ParameterLocation::Query, false),
			route("X-Trace", ParameterLocation::Header, false),
			ParameterRoute {
				name: "format".into(),
				location: ParameterLocation::Query,
				key: "query_format".into(),
				required: true
			},
		]
	);
}

#[tokio::test]
async fn a_collided_parameter_travels_by_its_location_and_the_body_keeps_its_own() {
	let server = MockServer::start().await;
	let host = server.uri();
	let parsed = reqwest::Url::parse(&host).unwrap();
	let (tool, mut upstream, _) = only_tool(&doc(json!({
		"/jobs": {
			"post": {
				"operationId": "submit",
				"parameters": [{"name": "format", "in": "query", "schema": {"type": "string"}}],
				"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"format": {"type": "string"}, "code": {"type": "string"}}}}}},
				"responses": {}
			}
		}
	})));
	upstream.base_path = None;
	let handler = handler_for(&parsed, vec![(tool, upstream)]).await;
	Mock::given(method("POST"))
		.and(path("/jobs"))
		.and(query_param("format", "json"))
		.and(body_json(json!({"format": "py", "code": "print(1)"})))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
		.expect(1)
		.mount(&server)
		.await;
	let result = handler
		.call_tool(
			"submit",
			Some(
				json!({"query_format": "json", "format": "py", "code": "print(1)"})
					.as_object()
					.unwrap()
					.clone(),
			),
			&IncomingRequestContext::empty(),
		)
		.await
		.expect("the call succeeds");
	assert_eq!(result.structured_content, Some(json!({"ok": true})));
}

async fn handler_for(parsed: &reqwest::Url, tools: Vec<(Tool, UpstreamOpenAPICall)>) -> Handler {
	let config = crate::config::parse_config("{}".to_string(), None).unwrap();
	let encoder = config.session_encoder.clone();
	let stores = Stores::with_ipv6_enabled(config.ipv6_enabled);
	let client = Client::new(
		&client::Config {
			resolver_cfg: ResolverConfig::default(),
			resolver_opts: ResolverOpts::default(),
		},
		None,
		BackendConfig::default(),
		None,
	);
	let pi = Arc::new(ProxyInputs {
		cfg: Arc::new(config),
		stores: stores.clone(),
		metrics: Arc::new(crate::metrics::Metrics::new(
			metrics::sub_registry(&mut Registry::default()),
			Default::default(),
			Default::default(),
		)),
		model_catalog: crate::llm::catalog::ModelCatalog::empty(),
		admin: None,
		upstream: client.clone(),
		ca: None,
		spiffe: None,
		mcp_state: mcp::router::App::new(stores.clone(), encoder),
		admission: Default::default(),
	});
	let client = PolicyClient::new(pi.clone());
	let backend = SimpleBackend::Opaque(
		ResourceName::new(strng::literal!("dummy"), "".into()),
		Target::Hostname(
			parsed.host().unwrap().to_string().into(),
			parsed.port().unwrap_or(8080),
		),
	);
	let upstream_client = super::super::McpHttpClient::new(
		client,
		backend,
		BackendPolicies::default(),
		false,
		"test-target".to_string(),
	);
	Handler::new(upstream_client, tools, "".to_string())
}

#[test]
fn a_root_ref_body_is_inlined_and_its_closure_lands_under_defs() {
	let (tool, _, _) = only_tool(&doc_with(
		json!({"components": {"schemas": {
			"Job": {"type": "object", "properties": {"step": {"$ref": "#/components/schemas/Step"}, "next": {"$ref": "#/components/schemas/Job"}}},
			"Step": {"type": "object", "properties": {"name": {"type": "string"}}}
		}}}),
		post_body(json!({"$ref": "#/components/schemas/Job"})),
	));
	assert_eq!(tool.input_schema["type"], json!("object"));
	assert_eq!(
		tool.input_schema["properties"]["step"],
		json!({"$ref": "#/$defs/Step"})
	);
	assert_eq!(
		tool.input_schema["properties"]["next"],
		json!({"$ref": "#/$defs/Job"})
	);
	let defs = tool.input_schema["$defs"].as_object().unwrap();
	assert!(defs.contains_key("Job") && defs.contains_key("Step"));
}

#[test]
fn a_composition_root_is_wrapped_and_a_bare_root_typed() {
	let (wrapped, _, _) = only_tool(&doc(post_body(
		json!({"oneOf": [{"type": "object"}, {"type": "string"}]}),
	)));
	assert_eq!(wrapped.input_schema["type"], json!("object"));
	assert_eq!(
		wrapped.input_schema["allOf"],
		json!([{"oneOf": [{"type": "object"}, {"type": "string"}]}])
	);

	let (bare, _, _) = only_tool(&doc(post_body(
		json!({"properties": {"a": {"type": "string"}}}),
	)));
	assert_eq!(bare.input_schema["type"], json!("object"));
	assert_eq!(
		bare.input_schema["properties"]["a"],
		json!({"type": "string"})
	);
}

#[test]
fn a_closed_composition_root_is_opened_for_its_parameters_with_a_warning() {
	let (tool, _, warnings) = only_tool(&doc(json!({
		"/jobs/{id}": {
			"put": {
				"operationId": "replaceJob",
				"parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
				"requestBody": {"content": {"application/json": {"schema": {"allOf": [{"type": "object", "properties": {"code": {"type": "string"}}}], "additionalProperties": false}}}},
				"responses": {}
			}
		}
	})));
	assert_eq!(
		tool.input_schema["allOf"],
		json!([{"allOf": [{"type": "object", "properties": {"code": {"type": "string"}}}]}])
	);
	assert_eq!(tool.input_schema["required"], json!(["id"]));
	assert!(
		warnings.contains(
			&"replaceJob: closed request body opened at the root so its parameters can sit beside it"
				.to_string()
		)
	);
}

#[test]
fn read_only_properties_leave_the_input_and_write_only_ones_leave_the_output() {
	let (tool, _, _) = only_tool(&doc(json!({
		"/things": {
			"post": {
				"operationId": "makeThing",
				"requestBody": {"content": {"application/json": {"schema": {
					"type": "object", "required": ["id", "name"],
					"properties": {"id": {"type": "string", "readOnly": true}, "name": {"type": "string"}, "secret": {"type": "string", "writeOnly": true}}
				}}}},
				"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {
					"type": "object", "properties": {"id": {"type": "string"}, "secret": {"type": "string", "writeOnly": true}}
				}}}}}
			}
		}
	})));
	let input_props = tool.input_schema["properties"].as_object().unwrap();
	assert!(
		!input_props.contains_key("id")
			&& input_props.contains_key("name")
			&& input_props.contains_key("secret")
	);
	assert_eq!(tool.input_schema["required"], json!(["name"]));
	let output = tool
		.output_schema
		.expect("an object output schema is advertised");
	let output_props = output["properties"].as_object().unwrap();
	assert!(output_props.contains_key("id") && !output_props.contains_key("secret"));
}

#[test]
fn openapi_only_keywords_are_stripped_and_a_singular_example_folds_into_examples() {
	let (tool, _, _) = only_tool(&doc(post_body(json!({
		"type": "object",
		"discriminator": {"propertyName": "kind"},
		"xml": {"name": "thing"},
		"externalDocs": {"url": "https://example.com"},
		"example": {"a": 1},
		"properties": {"a": {"type": "integer", "example": 1}}
	}))));
	assert!(
		tool.input_schema.get("discriminator").is_none()
			&& tool.input_schema.get("xml").is_none()
			&& tool.input_schema.get("externalDocs").is_none()
	);
	assert_eq!(tool.input_schema["examples"], json!([{"a": 1}]));
	assert_eq!(
		tool.input_schema["properties"]["a"],
		json!({"type": "integer", "examples": [1]})
	);
}

#[test]
fn the_3_0_dialect_is_translated_to_2020_12_and_3_1_moves_verbatim() {
	let schema = json!({
		"type": "object",
		"properties": {
			"name": {"type": "string", "nullable": true},
			"mode": {"type": "string", "enum": ["fast", "slow"], "nullable": true},
			"above": {"type": "integer", "minimum": 0, "exclusiveMinimum": true},
			"inclusive": {"type": "integer", "minimum": 0, "exclusiveMinimum": false}
		}
	});
	// (integer, not number: the typed 3.0 model writes a number bound back as a float, 0.0)
	let mut v30 = doc(post_body(schema.clone()));
	v30.openapi = "3.0.3".into();
	let (tool, _, warnings) = only_tool(&v30);
	assert_eq!(
		tool.input_schema["properties"],
		json!({
			"name": {"type": ["string", "null"]},
			"mode": {"type": ["string", "null"], "enum": ["fast", "slow", null]},
			"above": {"type": "integer", "exclusiveMinimum": 0},
			"inclusive": {"type": "integer", "minimum": 0}
		})
	);
	assert!(warnings[0].starts_with("document declares OpenAPI 3.0.3: schemas translated"));

	let (tool, _, warnings) = only_tool(&doc(post_body(json!({
		"type": "object",
		"properties": {"name": {"type": ["string", "null"]}, "above": {"type": "number", "exclusiveMinimum": 0}, "kind": {"const": "widget"}}
	}))));
	assert_eq!(
		tool.input_schema["properties"],
		json!({
			"name": {"type": ["string", "null"]}, "above": {"type": "number", "exclusiveMinimum": 0}, "kind": {"const": "widget"}
		})
	);
	assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn json_media_type_suffixes_and_ranges_count_as_json() {
	for media in [
		"application/vnd.api+json",
		"application/json; charset=utf-8",
		"application/*",
		"*/*",
	] {
		let (tool, upstream, _) = only_tool(&doc(json!({
			"/items": {"post": {"operationId": "put", "requestBody": {"content": {media: {"schema": {"type": "object", "properties": {"a": {"type": "string"}}}}}}, "responses": {}}}
		})));
		assert!(upstream.request_body, "{media}");
		assert_eq!(
			tool.input_schema["properties"]["a"],
			json!({"type": "string"}),
			"{media}"
		);
	}
}

#[test]
fn several_distinct_success_payloads_become_an_any_of_and_only_objects_are_advertised() {
	let (tool, _, _) = only_tool(&doc(json!({
		"/items": {"get": {"operationId": "list", "responses": {
			"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object", "properties": {"a": {"type": "string"}}}}}},
			"202": {"description": "later", "content": {"application/json": {"schema": {"type": "object", "properties": {"b": {"type": "string"}}}}}}
		}}}
	})));
	// anyOf has no root type, so it is kept for the resource later, not advertised as the tool's output.
	assert!(tool.output_schema.is_none());

	let (tool, _, _) = only_tool(&doc(json!({
		"/items": {"get": {"operationId": "list", "responses": {
			"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "array", "items": {"type": "string"}}}}}
		}}}
	})));
	assert!(
		tool.output_schema.is_none(),
		"a non-object output is not advertised"
	);
}

#[test]
fn an_operation_without_an_operation_id_is_skipped_with_a_warning_not_a_failed_target() {
	let (tools, warnings) = super::parse_openapi_schema_with_warnings(&doc(json!({
		"/a": {"get": {"responses": {}}},
		"/b": {"get": {"operationId": "b", "responses": {}}}
	})))
	.expect("the target loads");
	assert_eq!(
		tools
			.iter()
			.map(|(t, _)| t.name.to_string())
			.collect::<Vec<_>>(),
		["b"]
	);
	assert!(warnings.contains(&"GET /a skipped: no operationId".to_string()));
}

#[test]
fn an_external_ref_is_stubbed_with_a_warning() {
	let (tool, _, warnings) = only_tool(&doc(post_body(
		json!({"type": "object", "properties": {"x": {"$ref": "https://elsewhere/schema.json"}}}),
	)));
	assert_eq!(tool.input_schema["properties"]["x"], json!({}));
	assert!(
		warnings.contains(&"external $ref not followed: https://elsewhere/schema.json".to_string())
	);
}

#[test]
fn an_operation_level_server_contributes_its_path_over_the_documents() {
	let (_, with_op, _) = only_tool(&doc_with(
		json!({"servers": [{"url": "https://svc/doc"}]}),
		json!({"/x": {"servers": [{"url": "/item"}], "get": {"operationId": "x", "servers": [{"url": "https://h/{v}/op", "variables": {"v": {"default": "v2"}}}], "responses": {}}}}),
	));
	assert_eq!(with_op.base_path.as_deref(), Some("/v2/op"));
	let (_, with_item, _) = only_tool(&doc_with(
		json!({"servers": [{"url": "https://svc/doc"}]}),
		json!({"/x": {"servers": [{"url": "/item/"}], "get": {"operationId": "x", "responses": {}}}}),
	));
	assert_eq!(with_item.base_path.as_deref(), Some("/item"));
	let (_, none, _) = only_tool(&doc_with(
		json!({"servers": [{"url": "https://svc/doc"}]}),
		json!({"/x": {"get": {"operationId": "x", "responses": {}}}}),
	));
	assert_eq!(
		none.base_path, None,
		"the document's servers are the handler's prefix, not the route's"
	);
}

#[test]
fn a_3_1_document_with_what_3_1_adds_reads_without_loss() {
	let (tool, _, warnings) = only_tool(&doc_with(
		json!({"components": {"schemas": {"Owner": {"type": "object", "properties": {"id": {"type": "integer", "exclusiveMinimum": 0}}}}}}),
		post_body(json!({
			"type": "object",
			"properties": {
				"nickname": {"type": ["string", "null"]},
				"priority": {"type": "integer", "exclusiveMinimum": 0, "exclusiveMaximum": 10},
				"kind": {"const": "widget"},
				"tags": {"type": "array", "prefixItems": [{"type": "string"}], "items": false},
				"owner": {"$ref": "#/components/schemas/Owner", "description": "who", "writeOnly": true}
			}
		})),
	));
	let props = &tool.input_schema["properties"];
	assert_eq!(props["nickname"]["type"], json!(["string", "null"]));
	assert_eq!(props["priority"]["exclusiveMinimum"], json!(0));
	assert_eq!(props["kind"]["const"], json!("widget"));
	assert_eq!(props["tags"]["prefixItems"], json!([{"type": "string"}]));
	assert_eq!(props["tags"]["items"], json!(false));
	assert_eq!(props["owner"]["$ref"], json!("#/$defs/Owner"));
	assert_eq!(props["owner"]["description"], json!("who"));
	assert_eq!(
		tool.input_schema["$defs"]["Owner"]["properties"]["id"]["exclusiveMinimum"],
		json!(0)
	);
	assert!(warnings.is_empty(), "{warnings:?}");
}
