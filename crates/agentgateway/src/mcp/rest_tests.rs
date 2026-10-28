use std::sync::Arc;

use agent_core::{metrics, strng};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use http::{Method, StatusCode};
use openapiv3::OpenAPI;
use prometheus_client::registry::Registry;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::client::Client;
use crate::http::authorization::{PolicySet, RuleSet, RuleSets};
use crate::mcp::rbac::McpAuthorizationSet;
use crate::mcp::router::{McpBackendGroup, McpTarget};
use crate::store::Stores;
use crate::types::agent::{
	McpTargetSpec, OpenAPITarget, ResourceName, SimpleBackend, SimpleBackendReference, Target,
};
use crate::{BackendConfig, ProxyInputs, client, mcp};

fn document() -> OpenAPI {
	serde_json::from_value(json!({
		"openapi": "3.1.0",
		"info": { "title": "Items", "version": "2.0.0" },
		"servers": [{ "url": "https://items.internal/v1" }],
		"paths": {
			"/items": {
				"post": {
					"operationId": "createItem",
					"requestBody": { "required": true, "content": { "application/json": { "schema": {
						"type": "object", "properties": { "name": { "type": "string" } } } } } },
					"responses": { "201": { "description": "created" } }
				}
			},
			"/items/latest": {
				"get": { "operationId": "latestItem", "responses": { "200": { "description": "ok" } } }
			},
			"/items/{id}": {
				"get": {
					"operationId": "getItem",
					"parameters": [
						{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
						{ "name": "verbose", "in": "query", "schema": { "type": "boolean" } },
						{ "name": "x-trace", "in": "header", "schema": { "type": "string" } }
					],
					"responses": { "200": { "description": "ok" } }
				},
				"delete": { "operationId": "deleteItem", "responses": { "204": { "description": "gone" } } }
			}
		}
	}))
	.expect("valid document")
}

fn policy_client() -> PolicyClient {
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
		upstream: client,
		ca: None,
		spiffe: None,
		mcp_state: mcp::router::App::new(stores, encoder),
		admission: Default::default(),
	});
	PolicyClient::new(pi)
}

fn openapi_target(name: &str, addr: std::net::SocketAddr, schema: OpenAPI) -> Arc<McpTarget> {
	Arc::new(McpTarget {
		name: name.into(),
		condition: None,
		spec: McpTargetSpec::OpenAPI(OpenAPITarget {
			backend: SimpleBackendReference::Backend(strng::format!("/{name}")),
			schema: Arc::new(schema),
		}),
		backend_policies: Default::default(),
		backend: Some(SimpleBackend::Opaque(
			ResourceName::new(strng::format!("{name}"), "".into()),
			Target::Address(addr),
		)),
	})
}

fn mcp_target(name: &str, addr: std::net::SocketAddr) -> Arc<McpTarget> {
	Arc::new(McpTarget {
		name: name.into(),
		condition: None,
		spec: McpTargetSpec::Mcp(crate::types::agent::StreamableHTTPTargetSpec {
			backend: SimpleBackendReference::Backend(strng::format!("/{name}")),
			path: "/mcp".into(),
		}),
		backend_policies: Default::default(),
		backend: Some(SimpleBackend::Opaque(
			ResourceName::new(strng::format!("{name}"), "".into()),
			Target::Address(addr),
		)),
	})
}

fn no_rules() -> McpAuthorizationSet {
	McpAuthorizationSet::new(RuleSets::from(vec![]))
}

fn allow(expr: &str) -> McpAuthorizationSet {
	let policies = PolicySet::new(
		vec![Arc::new(crate::cel::Expression::new_strict(expr).unwrap())],
		vec![],
		vec![],
	);
	McpAuthorizationSet::new(RuleSets::from(vec![RuleSet::new(policies)]))
}

async fn call(
	targets: Vec<Arc<McpTarget>>,
	policies: McpAuthorizationSet,
	req: Request,
) -> (StatusCode, http::HeaderMap, Value) {
	let inputs = Inputs {
		backend: McpBackendGroup {
			targets,
			..Default::default()
		},
		policies,
		client: policy_client(),
	};
	let resp = serve(req, inputs).await.expect("a response");
	let (parts, body) = resp.into_parts();
	let bytes = crate::http::read_body_with_limit(body, 1 << 20)
		.await
		.unwrap();
	let body = if bytes.is_empty() {
		Value::Null
	} else {
		serde_json::from_slice(&bytes).unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()))
	};
	(parts.status, parts.headers, body)
}

fn get(uri: &str) -> Request {
	::http::Request::builder()
		.method(Method::GET)
		.uri(uri)
		.body(Body::empty())
		.unwrap()
}

#[tokio::test]
async fn lists_the_openapi_targets_only() {
	let server = MockServer::start().await;
	let (status, _, body) = call(
		vec![
			openapi_target("items", server.address().to_owned(), document()),
			mcp_target("tools", server.address().to_owned()),
		],
		no_rules(),
		get("http://gw/rest/"),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		body,
		json!({ "services": [{
			"name": "items",
			"title": "Items",
			"version": "2.0.0",
			"openapi": "/rest/items/openapi.json",
			"operations": 4
		}] })
	);
}

#[tokio::test]
async fn serves_the_document_with_servers_pointing_back_at_the_gateway() {
	let server = MockServer::start().await;
	let (status, headers, body) = call(
		vec![openapi_target(
			"items",
			server.address().to_owned(),
			document(),
		)],
		no_rules(),
		get("http://gw/rest/items/openapi.json"),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers[http::header::CONTENT_TYPE], "application/json");
	assert_eq!(body["openapi"], "3.1.0");
	assert_eq!(body["servers"], json!([{ "url": "/rest/items" }]));
	assert_eq!(body["info"]["title"], "Items");
	assert_eq!(
		body["paths"]["/items/{id}"]["get"]["parameters"][1]["name"],
		"verbose"
	);
	assert_eq!(
		body["paths"]["/items"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]
			["name"]["type"],
		"string"
	);
}

#[tokio::test]
async fn forwards_an_operation_under_the_document_server_path() {
	let server = MockServer::start().await;
	Mock::given(method("GET"))
		.and(path("/v1/items/42"))
		.and(query_param("verbose", "true"))
		.and(header("x-trace", "abc"))
		.and(header("authorization", "Bearer t"))
		.respond_with(
			ResponseTemplate::new(200)
				.insert_header("content-type", "application/json")
				.insert_header("x-upstream", "yes")
				.set_body_json(json!({ "id": "42" })),
		)
		.expect(1)
		.mount(&server)
		.await;
	let req = ::http::Request::builder()
		.method(Method::GET)
		.uri("http://gw/rest/items/items/42?verbose=true")
		.header("x-trace", "abc")
		.header("authorization", "Bearer t")
		.header("connection", "keep-alive, x-hop")
		.header("x-hop", "no")
		.header("mcp-session-id", "s1")
		.body(Body::empty())
		.unwrap();
	let (status, headers, body) = call(
		vec![openapi_target(
			"items",
			server.address().to_owned(),
			document(),
		)],
		no_rules(),
		req,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, json!({ "id": "42" }));
	assert_eq!(headers["x-upstream"], "yes");
	let received = &server.received_requests().await.unwrap()[0];
	assert!(
		received.headers.get("x-hop").is_none(),
		"hop-by-hop header crossed"
	);
	assert!(received.headers.get("connection").is_none());
	assert!(received.headers.get("mcp-session-id").is_none());
}

#[tokio::test]
async fn forwards_a_body_unchanged() {
	let server = MockServer::start().await;
	Mock::given(method("POST"))
		.and(path("/v1/items"))
		.and(header("content-type", "application/json"))
		.and(body_json(json!({ "name": "pen" })))
		.respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": "7" })))
		.expect(1)
		.mount(&server)
		.await;
	let req = ::http::Request::builder()
		.method(Method::POST)
		.uri("http://gw/rest/items/items")
		.header("content-type", "application/json")
		.body(Body::from(
			serde_json::to_vec(&json!({ "name": "pen" })).unwrap(),
		))
		.unwrap();
	let (status, _, body) = call(
		vec![openapi_target(
			"items",
			server.address().to_owned(),
			document(),
		)],
		no_rules(),
		req,
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	assert_eq!(body, json!({ "id": "7" }));
}

#[tokio::test]
async fn a_literal_path_wins_over_a_template() {
	let server = MockServer::start().await;
	Mock::given(method("GET"))
		.and(path("/v1/items/latest"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({ "latest": true })))
		.expect(1)
		.mount(&server)
		.await;
	let (status, _, body) = call(
		vec![openapi_target(
			"items",
			server.address().to_owned(),
			document(),
		)],
		no_rules(),
		get("http://gw/rest/items/items/latest"),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, json!({ "latest": true }));
}

#[tokio::test]
async fn passes_upstream_errors_through_unchanged() {
	let server = MockServer::start().await;
	Mock::given(method("GET"))
		.and(path("/v1/items/missing"))
		.respond_with(ResponseTemplate::new(404).set_body_json(json!({ "error": "no item" })))
		.mount(&server)
		.await;
	Mock::given(method("GET"))
		.and(path("/v1/items/broken"))
		.respond_with(ResponseTemplate::new(500).set_body_string("boom"))
		.mount(&server)
		.await;
	let targets = vec![openapi_target(
		"items",
		server.address().to_owned(),
		document(),
	)];
	let (status, _, body) = call(
		targets.clone(),
		no_rules(),
		get("http://gw/rest/items/items/missing"),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body, json!({ "error": "no item" }));
	let (status, _, body) = call(
		targets,
		no_rules(),
		get("http://gw/rest/items/items/broken"),
	)
	.await;
	assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
	assert_eq!(body, json!("boom"));
}

#[tokio::test]
async fn does_not_forward_what_the_document_does_not_describe() {
	let server = MockServer::start().await;
	let targets = vec![openapi_target(
		"items",
		server.address().to_owned(),
		document(),
	)];

	let (status, _, body) = call(
		targets.clone(),
		no_rules(),
		get("http://gw/rest/items/admin/users"),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(
		body,
		json!({ "error": "GET /admin/users is not an operation of items" })
	);

	let (status, _, body) = call(
		targets.clone(),
		no_rules(),
		get("http://gw/rest/items/items/1/2"),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(body["error"].as_str().unwrap().contains("not an operation"));

	let req = ::http::Request::builder()
		.method(Method::PUT)
		.uri("http://gw/rest/items/items/42")
		.body(Body::empty())
		.unwrap();
	let (status, headers, _) = call(targets.clone(), no_rules(), req).await;
	assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
	assert_eq!(headers[http::header::ALLOW], "DELETE, GET");

	let (status, _, body) = call(
		targets.clone(),
		no_rules(),
		get("http://gw/rest/nothing/items"),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body, json!({ "error": "no service named nothing" }));

	// an MCP target has no REST surface
	let (status, _, _) = call(
		vec![mcp_target("tools", server.address().to_owned())],
		no_rules(),
		get("http://gw/rest/tools/openapi.json"),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn a_tool_authorization_rule_hides_the_operation() {
	let server = MockServer::start().await;
	Mock::given(method("GET"))
		.and(path("/v1/items/42"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "42" })))
		.expect(1)
		.mount(&server)
		.await;
	let targets = vec![openapi_target(
		"items",
		server.address().to_owned(),
		document(),
	)];
	let rules = allow(r#"mcp.tool.name != "deleteItem""#);

	let req = ::http::Request::builder()
		.method(Method::DELETE)
		.uri("http://gw/rest/items/items/42")
		.body(Body::empty())
		.unwrap();
	let (status, _, _) = call(targets.clone(), rules.clone(), req).await;
	assert_eq!(status, StatusCode::NOT_FOUND);

	let (status, _, _) = call(targets, rules, get("http://gw/rest/items/items/42")).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn rest_paths() {
	assert!(is_rest_path("/rest"));
	assert!(is_rest_path("/rest/"));
	assert!(is_rest_path("/rest/items/openapi.json"));
	assert!(!is_rest_path("/restful"));
	assert!(!is_rest_path("/mcp"));
}
