//! `/rest/`: the OpenAPI targets of an MCP backend, as plain HTTP.
//!
//! A service registered as an OpenAPI target is reachable as MCP tools under `/mcp`. This
//! serves the same service, over the same backend, policies and header pass-through, to
//! clients that speak HTTP rather than MCP:
//!
//! - `GET /rest/` lists the OpenAPI targets.
//! - `GET /rest/<target>/openapi.json` serves a target's document as registered, with
//!   `servers` pointing back at `/rest/<target>`, so any OpenAPI client or generated SDK
//!   works against the gateway URL.
//! - Every other `/rest/<target>/<path>` is matched against the document's operations and
//!   forwarded as it is: method, query, headers and body unchanged, the path placed under
//!   the document's server path. A path the document does not describe is not forwarded,
//!   and a tool authorization rule that hides an operation's tool hides its path too.

use http::header::{self, HeaderName};
use http::uri::{PathAndQuery, Scheme};
use http::{HeaderMap, Method, StatusCode};
use rmcp::transport::common::http_header::HEADER_SESSION_ID;
use serde_json::{Value, json};

use crate::http::{Body, Request, Response};
use crate::mcp::guardrails::methods::TOOLS_CALL;
use crate::mcp::rbac::{CelExecWrapper, McpAuthorizationSet, ResourceId, ResourceType};
use crate::mcp::router::{McpBackendGroup, McpTarget};
use crate::mcp::upstream::openapi::{self, UpstreamOpenAPICall};
use crate::mcp::upstream::{IncomingRequestContext, McpHttpClient};
use crate::mcp::{MCPInfo, MCPTarget, MCPTool};
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::log::AsyncLog;
use crate::types::agent::{McpTargetSpec, OpenAPITarget};

pub(crate) const PREFIX: &str = "/rest";

pub(crate) fn is_rest_path(path: &str) -> bool {
	path == PREFIX || path.starts_with("/rest/")
}

pub(crate) struct Inputs {
	pub backend: McpBackendGroup,
	pub policies: McpAuthorizationSet,
	pub client: PolicyClient,
}

pub(crate) async fn serve(req: Request, inputs: Inputs) -> Result<Response, ProxyError> {
	let (parts, body) = req.into_parts();
	let rest = parts
		.uri
		.path()
		.strip_prefix(PREFIX)
		.unwrap_or("")
		.trim_start_matches('/');
	let (target_name, remainder) = match rest.find('/') {
		Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
		None => (rest.to_string(), "/".to_string()),
	};
	let ctx = IncomingRequestContext::new(&parts);
	if target_name.is_empty() {
		return Ok(if parts.method == Method::GET {
			list(&ctx, &inputs.backend)
		} else {
			method_not_allowed(&["GET"])
		});
	}
	let ctx = ctx.with_mcp_target(&target_name);
	let Some((target, open)) = find_target(&inputs.backend, &target_name, &ctx) else {
		return Ok(error_response(
			StatusCode::NOT_FOUND,
			&format!("no service named {target_name}"),
		));
	};
	if let Some(log) = parts.extensions.get::<AsyncLog<MCPInfo>>() {
		log.mutate_or_default(|m| {
			m.target = Some(MCPTarget {
				name: target_name.clone(),
			})
		});
	}

	if remainder == "/openapi.json" {
		return Ok(if parts.method == Method::GET {
			document(&target_name, open)
		} else {
			method_not_allowed(&["GET"])
		});
	}

	let tools = openapi::parse_openapi_schema(&open.schema)
		.map_err(|e| ProxyError::MCP(crate::mcp::Error::OpenAPI(e)))?;
	let prefix = openapi::get_server_prefix(&open.schema)
		.map_err(|e| ProxyError::MCP(crate::mcp::Error::OpenAPI(e)))?;
	let (tool_name, call) = match route(&tools, &parts.method, &remainder) {
		Route::Found(name, call) => (name, call),
		Route::MethodNotAllowed(allowed) => {
			return Ok(method_not_allowed(
				&allowed.iter().map(String::as_str).collect::<Vec<_>>(),
			));
		},
		Route::NotFound => {
			return Ok(error_response(
				StatusCode::NOT_FOUND,
				&format!(
					"{} {remainder} is not an operation of {target_name}",
					parts.method
				),
			));
		},
	};
	let allowed = inputs.policies.validate(
		&ResourceType::Tool(ResourceId::new(target_name.clone(), tool_name.clone())),
		&TOOLS_CALL,
		&CelExecWrapper::from(ctx),
	);
	if !allowed {
		// As on /mcp: an operation the caller may not use does not exist for them.
		return Ok(error_response(
			StatusCode::NOT_FOUND,
			&format!(
				"{} {remainder} is not an operation of {target_name}",
				parts.method
			),
		));
	}
	if let Some(log) = parts.extensions.get::<AsyncLog<MCPInfo>>() {
		log.mutate_or_default(|m| {
			m.tool = Some(MCPTool {
				target: target_name.clone(),
				name: tool_name.clone(),
				..Default::default()
			})
		});
	}

	let backend = target
		.backend
		.clone()
		.ok_or_else(|| ProxyError::ProcessingString("OpenAPI target without a backend".into()))?;
	let upstream_path =
		openapi::normalize_url_path(call.base_path.as_deref().unwrap_or(&prefix), &remainder);
	let path_and_query = match parts.uri.query() {
		Some(q) => format!("{upstream_path}?{q}"),
		None => upstream_path,
	};
	let hostport = backend.hostport();
	let mut req = Request::from_parts(parts, body);
	strip_hop_by_hop(req.headers_mut());
	req.headers_mut().remove(HEADER_SESSION_ID);
	crate::http::modify_req_uri(&mut req, |uri| {
		uri.scheme = Some(Scheme::HTTP);
		if uri.authority.is_none() {
			uri.authority = Some(hostport.parse()?);
		}
		uri.path_and_query = Some(PathAndQuery::try_from(path_and_query)?);
		Ok(())
	})
	.map_err(|e| ProxyError::ProcessingString(e.to_string()))?;

	let client = McpHttpClient::new(
		inputs.client,
		backend,
		target.backend_policies.clone(),
		false,
		target_name,
	);
	let mut response = client.call(req).await?;
	strip_hop_by_hop(response.headers_mut());
	Ok(response)
}

/// The OpenAPI targets of the backend that apply to this request, by name.
fn openapi_targets<'a>(
	backend: &'a McpBackendGroup,
	ctx: &IncomingRequestContext,
) -> impl Iterator<Item = (&'a McpTarget, &'a OpenAPITarget)> {
	let ctx = ctx.clone();
	backend.targets.iter().filter_map(move |t| {
		let McpTargetSpec::OpenAPI(open) = &t.spec else {
			return None;
		};
		let applies = t.condition.as_ref().is_none_or(|condition| {
			ctx
				.clone()
				.with_mcp_target(&t.name)
				.executor()
				.eval_bool(condition)
		});
		applies.then_some((t.as_ref(), open))
	})
}

fn find_target<'a>(
	backend: &'a McpBackendGroup,
	name: &str,
	ctx: &IncomingRequestContext,
) -> Option<(&'a McpTarget, &'a OpenAPITarget)> {
	openapi_targets(backend, ctx).find(|(t, _)| t.name.as_str() == name)
}

fn list(ctx: &IncomingRequestContext, backend: &McpBackendGroup) -> Response {
	let services: Vec<Value> = openapi_targets(backend, ctx)
		.map(|(t, open)| {
			json!({
				"name": t.name.as_str(),
				"title": open.schema.info.title,
				"version": open.schema.info.version,
				"openapi": format!("{PREFIX}/{}/openapi.json", t.name),
				"operations": open.schema.operations().count(),
			})
		})
		.collect();
	json_response(StatusCode::OK, json!({ "services": services }))
}

/// The document as registered, served from the gateway: `servers` names `/rest/<target>`,
/// relative to the document's own URL, so a client resolves every operation against the
/// gateway it fetched the document from.
fn document(target_name: &str, open: &OpenAPITarget) -> Response {
	let mut doc = match serde_json::to_value(&*open.schema) {
		Ok(doc) => doc,
		Err(e) => {
			return error_response(
				StatusCode::INTERNAL_SERVER_ERROR,
				&format!("cannot serialize the document of {target_name}: {e}"),
			);
		},
	};
	if let Value::Object(map) = &mut doc {
		map.insert(
			"servers".to_string(),
			json!([{ "url": format!("{PREFIX}/{target_name}") }]),
		);
	}
	json_response(StatusCode::OK, doc)
}

enum Route<'a> {
	Found(String, &'a UpstreamOpenAPICall),
	MethodNotAllowed(Vec<String>),
	NotFound,
}

/// Match a request against the document's operations. Path templates match segment by
/// segment, `{param}` taking any one non-empty segment; among the templates a path fits,
/// the one with the most literal segments wins, so `/items/latest` beats `/items/{id}`.
fn route<'a>(
	tools: &'a [(rmcp::model::Tool, UpstreamOpenAPICall)],
	method: &Method,
	path: &str,
) -> Route<'a> {
	let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
	let mut best: Option<(usize, &str, &UpstreamOpenAPICall)> = None;
	let mut allowed: Vec<String> = Vec::new();
	for (tool, call) in tools {
		let Some(literals) = template_matches(&call.path, &segments) else {
			continue;
		};
		let call_method = call.method.to_ascii_uppercase();
		if !allowed.contains(&call_method) {
			allowed.push(call_method.clone());
		}
		if call_method != method.as_str() {
			continue;
		}
		if best.is_none_or(|(l, _, _)| literals > l) {
			best = Some((literals, tool.name.as_ref(), call));
		}
	}
	match best {
		Some((_, name, call)) => Route::Found(name.to_string(), call),
		None if !allowed.is_empty() => {
			allowed.sort();
			Route::MethodNotAllowed(allowed)
		},
		None => Route::NotFound,
	}
}

/// The number of literal segments when `template` fits `segments`.
fn template_matches(template: &str, segments: &[&str]) -> Option<usize> {
	let parts: Vec<&str> = template.trim_start_matches('/').split('/').collect();
	if parts.len() != segments.len() {
		return None;
	}
	let mut literals = 0;
	for (part, segment) in parts.iter().zip(segments) {
		if part.starts_with('{') && part.ends_with('}') {
			if segment.is_empty() {
				return None;
			}
		} else if part == segment {
			literals += 1;
		} else {
			return None;
		}
	}
	Some(literals)
}

// Hop-by-hop headers (RFC 7230 §6.1 and the RFC 2616 list), which describe this
// connection and must not cross to the next one.
static HOP_HEADERS: [HeaderName; 7] = [
	header::CONNECTION,
	HeaderName::from_static("proxy-connection"),
	HeaderName::from_static("keep-alive"),
	header::PROXY_AUTHENTICATE,
	header::TE,
	header::TRANSFER_ENCODING,
	header::UPGRADE,
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
	let nominated: Vec<HeaderName> = headers
		.get_all(header::CONNECTION)
		.into_iter()
		.filter_map(|v| v.to_str().ok())
		.flat_map(|v| v.split(','))
		.map(str::trim)
		.filter_map(|token| HeaderName::from_bytes(token.as_bytes()).ok())
		.collect();
	for h in nominated.iter().chain(HOP_HEADERS.iter()) {
		headers.remove(h);
	}
}

fn json_response(status: StatusCode, body: Value) -> Response {
	::http::Response::builder()
		.status(status)
		.header(header::CONTENT_TYPE, "application/json")
		.body(Body::from(serde_json::to_vec(&body).unwrap_or_default()))
		.expect("valid response")
}

fn error_response(status: StatusCode, message: &str) -> Response {
	json_response(status, json!({ "error": message }))
}

fn method_not_allowed(allowed: &[&str]) -> Response {
	let mut resp = error_response(
		StatusCode::METHOD_NOT_ALLOWED,
		&format!("allowed: {}", allowed.join(", ")),
	);
	if let Ok(v) = allowed.join(", ").parse() {
		resp.headers_mut().insert(header::ALLOW, v);
	}
	resp
}

#[cfg(test)]
#[path = "rest_tests.rs"]
mod tests;
