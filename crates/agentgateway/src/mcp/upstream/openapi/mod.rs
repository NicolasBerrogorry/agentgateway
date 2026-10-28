use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use ::http::header::{HeaderName, HeaderValue};
use agent_core::version::BuildInfo;
use base64::Engine;
use headers::HeaderMapExt;
use http::Method;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING};
use once_cell::sync::Lazy;
use openapiv3::OpenAPI;
use percent_encoding::{AsciiSet, utf8_percent_encode};
use regex::Regex;
use rmcp::model::{CallToolResult, ClientRequest, ContentBlock, JsonObject, JsonRpcRequest, Tool};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tracing::{debug, warn};

use crate::client::ResolvedDestination;
use crate::http::sessionpersistence;
use crate::mcp::mergestream;
use crate::mcp::mergestream::Messages;
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};

/// Where an operation's non-body inputs go on the wire.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ParameterLocation {
	Path,
	Query,
	Header,
	Cookie,
}

/// One declared parameter of an operation: what the service calls it, where it goes, and
/// the property of the tool's input schema that carries it (the name, or location-prefixed
/// when it collides with a body property). Everything else in the input is the body.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ParameterRoute {
	pub name: String,
	pub location: ParameterLocation,
	pub key: String,
	pub required: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct UpstreamOpenAPICall {
	pub method: String, /* TODO: Switch to Method, but will require getting rid of Serialize/Deserialize */
	pub path: String,
	pub allowed_headers: HashSet<String>,
	#[serde(default)]
	pub content_type: Option<String>,
	/// The declared parameters, which route a flat argument object onto the wire.
	#[serde(default)]
	pub parameters: Vec<ParameterRoute>,
	/// Whether the operation declares a JSON request body: the arguments no parameter
	/// claims are sent as it. A body-less operation sends none.
	#[serde(default)]
	pub request_body: bool,
	/// The path an operation-level or path-item-level `servers` entry contributes; the
	/// closest declaration wins over the document's, which is the handler's prefix.
	#[serde(default)]
	pub base_path: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
	#[error("missing components")]
	MissingComponents,
	#[error("missing reference")]
	MissingReference(String),
	#[error("unsupported reference")]
	UnsupportedReference(String),
	#[error("information required: {0}")]
	InformationRequired(String),
	#[error("serde error: {0}")]
	SerdeError(#[from] serde_json::Error),
	#[error("io error: {0}")]
	IoError(#[from] std::io::Error),
	#[error("Invalid URL: {0}")]
	InvalidUrl(#[from] url::ParseError),
}

#[derive(Debug, thiserror::Error)]
enum PathParamError {
	#[error("path parameter '{0}' is missing")]
	Missing(String),
	#[error("path parameter '{0}' must be a string or number")]
	UnsupportedType(String),
	#[error("path parameter '{0}' must not be empty or contain a dot segment")]
	UnsafeSegment(String),
}

pub(crate) fn get_server_prefix(server: &OpenAPI) -> Result<String, ParseError> {
	match server.servers.len() {
		0 => Ok("".to_string()),
		1 => {
			let raw = &server.servers[0].url;

			let extract_path = |after_scheme: &str| -> String {
				if let Some(path_idx) = after_scheme.find('/') {
					let path = &after_scheme[path_idx..];
					let path = path.split('?').next().unwrap_or(path);
					let path = path.split('#').next().unwrap_or(path);
					let path = path.trim_end_matches('/');
					if path.is_empty() || path == "/" {
						"".to_string()
					} else {
						path.to_string()
					}
				} else {
					"".to_string()
				}
			};

			if let Some(idx) = raw.find("://") {
				Ok(extract_path(&raw[idx + 3..]))
			} else if let Some(stripped) = raw.strip_prefix("//") {
				Ok(extract_path(stripped))
			} else {
				// Not an absolute URL -- treat as a relative path prefix (existing behavior)
				if let Ok(parsed) = url::Url::parse(raw) {
					let path = parsed.path().trim_end_matches('/').to_string();
					if path.is_empty() || path == "/" {
						Ok("".to_string())
					} else {
						Ok(path)
					}
				} else {
					Ok(raw.clone())
				}
			}
		},
		_ => Err(ParseError::UnsupportedReference(format!(
			"multiple servers are not supported: {:?}",
			server.servers
		))),
	}
}

// ── The document reader ──────────────────────────────────────────────────────
//
// Reads the OpenAPI document as JSON and lifts, for every documented operation, a
// self-contained JSON Schema for its input, one for its output, and where each input
// goes on the wire. OpenAPI + JSON Schema vocabulary only.
//
// The version is read ONCE, at the entry, to pick the schema dialect: 3.1/3.2 Schema
// Objects ARE JSON Schema 2020-12 and move by copy; a 3.0 document's Schema Objects are
// translated on the copy (nullable, boolean exclusive bounds) so that every schema handed
// to a client is 2020-12 and nothing downstream asks what version a document was.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
	Oas30,
	JsonSchema202012,
}

fn dialect_of(version: &str) -> Dialect {
	if version.starts_with("3.0") {
		Dialect::Oas30
	} else {
		Dialect::JsonSchema202012
	}
}

/// Which properties a copy leaves out: readOnly ones when documenting an input,
/// writeOnly ones for an output.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Drop {
	ReadOnly,
	WriteOnly,
}

impl Drop {
	fn keyword(self) -> &'static str {
		match self {
			Drop::ReadOnly => "readOnly",
			Drop::WriteOnly => "writeOnly",
		}
	}
}

const HTTP_METHODS: [&str; 8] = [
	"get", "put", "post", "delete", "patch", "head", "options", "trace",
];
const SCHEMAS_PREFIX: &str = "#/components/schemas/";
const OPENAPI_ONLY_KEYWORDS: [&str; 3] = ["discriminator", "xml", "externalDocs"];
/// Keywords whose value is DATA, not a schema: copied as-is, never read as a schema.
const DATA_KEYWORDS: [&str; 4] = ["examples", "default", "const", "enum"];

// The 3.0 idioms with a 2020-12 equivalent, translated in place on a copied schema
// object. Everything else a 3.0 schema can say already means the same thing in 2020-12.
// `nullable` only has meaning next to a `type` (3.0.3 §4.7.24), so without one it is
// simply dropped.
fn translate_oas30(out: &mut Map<String, Value>) {
	if out.get("nullable") == Some(&Value::Bool(true)) {
		match out.get("type").cloned() {
			Some(Value::String(t)) => {
				out.insert("type".into(), json!([t, "null"]));
			},
			Some(Value::Array(mut types)) => {
				if !types.iter().any(|t| t == "null") {
					types.push(json!("null"));
				}
				out.insert("type".into(), Value::Array(types));
			},
			_ => {},
		}
		if out.contains_key("type")
			&& let Some(Value::Array(values)) = out.get("enum").cloned()
			&& !values.iter().any(Value::is_null)
		{
			let mut values = values;
			values.push(Value::Null);
			out.insert("enum".into(), Value::Array(values));
		}
	}
	out.remove("nullable");
	for (bound, exclusive) in [
		("minimum", "exclusiveMinimum"),
		("maximum", "exclusiveMaximum"),
	] {
		let Some(Value::Bool(flag)) = out.get(exclusive).cloned() else {
			continue;
		};
		match (flag, out.get(bound).cloned()) {
			(true, Some(n @ Value::Number(_))) => {
				out.insert(exclusive.into(), n);
				out.remove(bound);
			},
			_ => {
				out.remove(exclusive);
			},
		}
	}
}

// Resolve one internal reference ('#/a/b/c') by pointer walk. None for external or
// dangling references — callers decide how to degrade.
fn resolve_ref<'a>(doc: &'a Value, reference: &str) -> Option<&'a Map<String, Value>> {
	let pointer = reference.strip_prefix("#/")?;
	let mut node = doc;
	for raw in pointer.split('/') {
		let key = raw.replace("~1", "/").replace("~0", "~");
		node = node.as_object()?.get(&key)?;
	}
	node.as_object()
}

// A Parameter, Response or Request Body entry may itself be a Reference Object.
fn deref<'a>(doc: &'a Value, node: &'a Value) -> Option<&'a Map<String, Value>> {
	let object = node.as_object()?;
	match object.get("$ref") {
		Some(Value::String(reference)) => resolve_ref(doc, reference),
		_ => Some(object),
	}
}

fn str_of(v: Option<&Value>) -> Option<&str> {
	v.and_then(Value::as_str)
}

// The JSON schema inside a content map, matching media-type ranges and +json suffixes
// rather than requiring a literal 'application/json' key.
fn json_content_schema(content: Option<&Value>) -> Option<&Map<String, Value>> {
	let content = content?.as_object()?;
	let key = content.keys().find(|k| {
		let mt = k
			.split(';')
			.next()
			.unwrap_or("")
			.trim()
			.to_ascii_lowercase();
		mt == "application/json" || mt.ends_with("+json") || mt == "application/*" || mt == "*/*"
	})?;
	content.get(key)?.as_object()?.get("schema")?.as_object()
}

/// What one operation's input lifts to.
struct InputLift {
	schema: Map<String, Value>,
	parameters: Vec<ParameterRoute>,
	request_body: bool,
	content_type: Option<String>,
}

struct Reader<'a> {
	doc: &'a Value,
	dialect: Dialect,
	warnings: Vec<String>,
}

impl<'a> Reader<'a> {
	fn warn(&mut self, msg: String) {
		if !self.warnings.contains(&msg) {
			self.warnings.push(msg);
		}
	}

	// Copy a schema for standalone use: rewrite component-schema refs to $defs, resolve
	// other internal refs inline (once — cycles degrade to {}), stub external refs, strip
	// OpenAPI-only keywords, fold singular example into examples, translate the 3.0
	// dialect when that is what the document speaks, and drop the properties foreign to
	// the copy's direction.
	fn copy_schema(
		&mut self,
		node: &Value,
		needed: &mut BTreeSet<String>,
		inlining: &BTreeSet<String>,
		drop: Drop,
	) -> Value {
		let object = match node {
			Value::Array(items) => {
				return Value::Array(
					items
						.iter()
						.map(|n| self.copy_schema(n, needed, inlining, drop))
						.collect(),
				);
			},
			Value::Object(object) => object,
			other => return other.clone(),
		};

		if let Some(Value::String(reference)) = object.get("$ref") {
			if let Some(name) = reference.strip_prefix(SCHEMAS_PREFIX) {
				needed.insert(name.to_string());
				let mut out = object.clone();
				out.insert("$ref".into(), json!(format!("#/$defs/{name}")));
				return Value::Object(out);
			}
			if !reference.starts_with("#/") {
				self.warn(format!("external $ref not followed: {reference}"));
				return json!({});
			}
			if inlining.contains(reference) {
				self.warn(format!("cyclic non-schema $ref dropped: {reference}"));
				return json!({});
			}
			let Some(target) = resolve_ref(self.doc, reference) else {
				self.warn(format!("dangling $ref dropped: {reference}"));
				return json!({});
			};
			let target = Value::Object(target.clone());
			let mut inlining = inlining.clone();
			inlining.insert(reference.clone());
			return self.copy_schema(&target, needed, &inlining, drop);
		}

		let mut out = Map::new();
		let mut dropped = BTreeSet::new();
		for (key, value) in object {
			if OPENAPI_ONLY_KEYWORDS.contains(&key.as_str()) {
				continue;
			}
			if key == "example" {
				continue; // folded below
			}
			if DATA_KEYWORDS.contains(&key.as_str()) {
				out.insert(key.clone(), value.clone());
				continue;
			}
			if key == "properties"
				&& let Some(props) = value.as_object()
			{
				let mut copied = Map::new();
				for (name, prop) in props {
					if prop.get(drop.keyword()) == Some(&Value::Bool(true)) {
						dropped.insert(name.clone());
						continue;
					}
					copied.insert(name.clone(), self.copy_schema(prop, needed, inlining, drop));
				}
				out.insert("properties".into(), Value::Object(copied));
				continue;
			}
			out.insert(key.clone(), self.copy_schema(value, needed, inlining, drop));
		}
		if let Some(example) = object.get("example")
			&& !out.contains_key("examples")
		{
			out.insert("examples".into(), json!([example.clone()]));
		}
		if !dropped.is_empty()
			&& let Some(Value::Array(required)) = out.get("required").cloned()
		{
			let kept: Vec<Value> = required
				.into_iter()
				.filter(|r| r.as_str().is_none_or(|name| !dropped.contains(name)))
				.collect();
			if kept.is_empty() {
				out.remove("required");
			} else {
				out.insert("required".into(), Value::Array(kept));
			}
		}
		if self.dialect == Dialect::Oas30 {
			translate_oas30(&mut out);
		}
		Value::Object(out)
	}

	// Carry every referenced component schema (transitively) under $defs, so a lifted
	// schema stands alone outside its document.
	fn close_defs(&mut self, mut needed: BTreeSet<String>, drop: Drop) -> Option<Map<String, Value>> {
		let components = self
			.doc
			.get("components")
			.and_then(|c| c.get("schemas"))
			.and_then(Value::as_object)
			.cloned()
			.unwrap_or_default();
		let mut defs = Map::new();
		let mut done = BTreeSet::new();
		while needed.len() > done.len() {
			for name in needed.clone() {
				if !done.insert(name.clone()) {
					continue;
				}
				match components.get(&name) {
					Some(schema @ Value::Object(_)) => {
						let copy = self.copy_schema(schema, &mut needed, &BTreeSet::new(), drop);
						defs.insert(name, copy);
					},
					_ => self.warn(format!("dangling $ref dropped: {SCHEMAS_PREFIX}{name}")),
				}
			}
		}
		(!defs.is_empty()).then_some(defs)
	}

	fn lift_input_schema(
		&mut self,
		path_item: &Map<String, Value>,
		op: &Map<String, Value>,
	) -> InputLift {
		let doc = self.doc;
		let mut needed = BTreeSet::new();
		let request_body = op.get("requestBody").and_then(|rb| deref(doc, rb));
		let raw = request_body.and_then(|rb| json_content_schema(rb.get("content")));
		let body_required = request_body.and_then(|rb| rb.get("required")) == Some(&Value::Bool(true));
		// A binary body: one base64 string property, as the gateway has always offered it.
		let octet = raw.is_none()
			&& request_body
				.and_then(|rb| rb.get("content"))
				.and_then(Value::as_object)
				.is_some_and(|c| c.contains_key("application/octet-stream"));

		// Resolve a root-level $ref before copying: MCP requires the input schema's root to
		// be a literal object, and a `$ref` root also swallows the parameter merge below
		// (draft-07 consumers ignore $ref siblings). The referenced component's top layer
		// is inlined here; everything it references — itself included — still lands under
		// $defs through the copy.
		let body = raw.and_then(|r| deref(doc, &Value::Object(r.clone())).cloned());
		if let Some(raw) = raw
			&& body.is_none()
		{
			let reference = str_of(raw.get("$ref")).unwrap_or("");
			self.warn(if reference.starts_with("#/") {
				format!("dangling $ref dropped: {reference}")
			} else {
				format!("external $ref not followed: {reference}")
			});
		}
		let mut lifted = match body {
			Some(body) => self
				.copy_schema(
					&Value::Object(body),
					&mut needed,
					&BTreeSet::new(),
					Drop::ReadOnly,
				)
				.as_object()
				.cloned()
				.unwrap_or_default(),
			None => Map::new(),
		};
		let mut wrapped = false;
		if lifted.get("type").is_none() {
			// A composition root keeps its meaning one level down, so parameters merge into
			// the wrapper; a bare root just gains the type it already implied.
			wrapped = ["allOf", "anyOf", "oneOf"]
				.iter()
				.any(|k| lifted.contains_key(*k));
			if wrapped {
				let inner = Value::Object(std::mem::take(&mut lifted));
				lifted.insert("type".into(), json!("object"));
				lifted.insert("allOf".into(), json!([inner]));
			} else {
				lifted.insert("type".into(), json!("object"));
			}
		}
		if !lifted.get("properties").is_some_and(Value::is_object) {
			lifted.insert("properties".into(), json!({}));
		}
		let mut required: Vec<String> = lifted
			.get("required")
			.and_then(Value::as_array)
			.map(|r| {
				r.iter()
					.filter_map(Value::as_str)
					.map(String::from)
					.collect()
			})
			.unwrap_or_default();
		if octet {
			lifted["properties"]["body"] = json!({
				"type": "string",
				"format": "byte",
				"description": "Base64-encoded binary content"
			});
			if body_required && !required.iter().any(|r| r == "body") {
				required.push("body".into());
			}
		}

		// Merge path-item and operation parameters (operation wins on same name+location;
		// header names compare case-insensitively, as HTTP does) as sibling properties. A
		// name colliding with a body property is prefixed with its location rather than
		// silently overwritten; the location itself is recorded on `parameters`, which is
		// what routes the call.
		let mut params: Vec<(String, Map<String, Value>)> = Vec::new();
		for source in [path_item.get("parameters"), op.get("parameters")] {
			let Some(Value::Array(source)) = source else {
				continue;
			};
			for raw in source {
				let Some(p) = deref(doc, raw) else { continue };
				let (Some(name), Some(location)) = (str_of(p.get("name")), str_of(p.get("in"))) else {
					continue;
				};
				let location = match location {
					"path" => "path",
					"query" => "query",
					"header" => "header",
					"cookie" => "cookie",
					other => {
						self.warn(format!(
							"parameter \"{name}\" skipped: unknown location \"{other}\""
						));
						continue;
					},
				};
				let merge_name = if location == "header" {
					name.to_ascii_lowercase()
				} else {
					name.to_string()
				};
				let key = format!("{location}:{merge_name}");
				match params.iter_mut().find(|(k, _)| *k == key) {
					Some((_, existing)) => *existing = p.clone(),
					None => params.push((key, p.clone())),
				}
			}
		}
		let mut parameters = Vec::new();
		for (_, p) in params {
			let name = str_of(p.get("name")).unwrap_or_default().to_string();
			let location = match str_of(p.get("in")).unwrap_or_default() {
				"path" => ParameterLocation::Path,
				"query" => ParameterLocation::Query,
				"header" => ParameterLocation::Header,
				_ => ParameterLocation::Cookie,
			};
			let location_name = match location {
				ParameterLocation::Path => "path",
				ParameterLocation::Query => "query",
				ParameterLocation::Header => "header",
				ParameterLocation::Cookie => "cookie",
			};
			let properties = lifted["properties"]
				.as_object_mut()
				.expect("properties is an object");
			let key = if properties.contains_key(&name) {
				format!("{location_name}_{name}")
			} else {
				name.clone()
			};
			let mut schema = match p.get("schema") {
				Some(s @ Value::Object(_)) => self
					.copy_schema(s, &mut needed, &BTreeSet::new(), Drop::ReadOnly)
					.as_object()
					.cloned()
					.unwrap_or_default(),
				_ => Map::new(),
			};
			if let Some(description) = p.get("description")
				&& !schema.contains_key("description")
			{
				schema.insert("description".into(), description.clone());
			}
			if p.get("deprecated") == Some(&Value::Bool(true)) {
				schema.insert("deprecated".into(), json!(true));
			}
			let properties = lifted["properties"]
				.as_object_mut()
				.expect("properties is an object");
			properties.insert(key.clone(), Value::Object(schema));
			// OpenAPI requires a path parameter to be `required: true`; a document that omits
			// it still describes a mandatory value — the template has nowhere else to put it.
			let declared_required = p.get("required") == Some(&Value::Bool(true));
			let mandatory = location == ParameterLocation::Path || declared_required;
			if location == ParameterLocation::Path && !declared_required {
				self.warn(format!(
					"path parameter \"{name}\" declared optional; path parameters are always required"
				));
			}
			if mandatory && !required.contains(&key) {
				required.push(key.clone());
			}
			parameters.push(ParameterRoute {
				name,
				location,
				key,
				required: mandatory,
			});
		}
		if required.is_empty() {
			lifted.remove("required");
		} else {
			lifted.insert("required".into(), json!(required));
		}

		// A closed composition root (additionalProperties: false inside the wrapper's allOf)
		// would reject the very parameters merged beside it. The root is opened, with a
		// warning; the branches' own constraints are untouched.
		if wrapped
			&& !parameters.is_empty()
			&& let Some(inner) = lifted
				.get_mut("allOf")
				.and_then(Value::as_array_mut)
				.and_then(|a| a.first_mut())
				.and_then(Value::as_object_mut)
			&& inner.get("additionalProperties") == Some(&Value::Bool(false))
		{
			inner.remove("additionalProperties");
			let operation_id = str_of(op.get("operationId"))
				.unwrap_or_default()
				.to_string();
			self.warn(format!(
				"{operation_id}: closed request body opened at the root so its parameters can sit beside it"
			));
		}

		if let Some(defs) = self.close_defs(needed, Drop::ReadOnly) {
			lifted.insert("$defs".into(), Value::Object(defs));
		}
		InputLift {
			schema: lifted,
			parameters,
			request_body: raw.is_some(),
			content_type: octet.then(|| "application/octet-stream".to_string()),
		}
	}

	// The operation's success payload as a standalone schema: one 2xx JSON schema verbatim,
	// several distinct ones as anyOf, none as None. writeOnly properties drop — this copy
	// documents an output.
	fn lift_output_schema(&mut self, op: &Map<String, Value>) -> Option<Map<String, Value>> {
		let doc = self.doc;
		let responses = op
			.get("responses")
			.and_then(Value::as_object)
			.cloned()
			.unwrap_or_default();
		let mut needed = BTreeSet::new();
		let mut lifted: Vec<Value> = Vec::new();
		let mut seen = HashSet::new();
		for (status, raw) in &responses {
			if !status.starts_with('2') {
				continue;
			}
			let Some(schema) = deref(doc, raw).and_then(|r| json_content_schema(r.get("content"))) else {
				continue;
			};
			let copy = self.copy_schema(
				&Value::Object(schema.clone()),
				&mut needed,
				&BTreeSet::new(),
				Drop::WriteOnly,
			);
			if seen.insert(copy.to_string()) {
				lifted.push(copy);
			}
		}
		if lifted.is_empty() {
			return None;
		}
		let mut out = if lifted.len() == 1 {
			lifted.pop()?.as_object().cloned().unwrap_or_default()
		} else {
			let mut m = Map::new();
			m.insert("anyOf".into(), Value::Array(lifted));
			m
		};
		if let Some(defs) = self.close_defs(needed, Drop::WriteOnly) {
			out.insert("$defs".into(), Value::Object(defs));
		}
		Some(out)
	}

	// The path an operation-level or path-item-level `servers` entry contributes, the
	// closest winning; the document's own `servers` is the handler's prefix. Only the
	// first entry is read: a relative URL is the path itself; an absolute or
	// protocol-relative one contributes what follows its authority. Server variables take
	// their default.
	fn base_path(
		&mut self,
		path_item: &Map<String, Value>,
		op: &Map<String, Value>,
	) -> Option<String> {
		let servers = [op.get("servers"), path_item.get("servers")]
			.into_iter()
			.flatten()
			.find_map(|s| s.as_array().filter(|a| !a.is_empty()))?;
		let first = servers.first()?.as_object()?;
		let url = first.get("url")?.as_str()?;
		if servers.len() > 1 {
			self.warn(format!(
				"{} servers declared; only the first ({url}) is used",
				servers.len()
			));
		}
		let variables = first.get("variables").and_then(Value::as_object);
		let mut substituted = String::new();
		let mut rest = url;
		while let Some(open) = rest.find('{') {
			substituted.push_str(&rest[..open]);
			let Some(close) = rest[open..].find('}') else {
				substituted.push_str(&rest[open..]);
				rest = "";
				break;
			};
			let name = &rest[open + 1..open + close];
			match variables
				.and_then(|v| v.get(name))
				.and_then(|v| v.get("default"))
				.and_then(Value::as_str)
			{
				Some(fallback) => substituted.push_str(fallback),
				None => {
					self.warn(format!(
						"server variable \"{name}\" has no default; left as {{{name}}}"
					));
					substituted.push_str(&rest[open..open + close + 1]);
				},
			}
			rest = &rest[open + close + 1..];
		}
		substituted.push_str(rest);
		let url = substituted;
		let after_authority = if let Some(idx) = url.find("://") {
			Some(&url[idx + 3..])
		} else {
			url.strip_prefix("//")
		};
		let mut path = match after_authority {
			Some(rest) => rest.find('/').map(|slash| &rest[slash..]).unwrap_or(""),
			None => url.as_str(),
		}
		.to_string();
		path = path
			.split('?')
			.next()
			.unwrap_or("")
			.split('#')
			.next()
			.unwrap_or("")
			.to_string();
		let path = path.trim_end_matches('/');
		if path.is_empty() {
			return Some(String::new());
		}
		Some(if path.starts_with('/') {
			path.to_string()
		} else {
			format!("/{path}")
		})
	}
}

/// The tools of a document and the warnings raised for operations left out.
pub(crate) type ParsedWithWarnings = (Vec<(Tool, UpstreamOpenAPICall)>, Vec<String>);

/// Every documented operation as a tool and its route, plus what was read imperfectly
/// (external refs, skipped operations, forced parameters…): an operation that cannot be
/// read degrades to a warning, never to a failed target.
pub(crate) fn parse_openapi_schema_with_warnings(
	open_api: &OpenAPI,
) -> Result<ParsedWithWarnings, ParseError> {
	let doc = serde_json::to_value(open_api).map_err(ParseError::SerdeError)?;
	let dialect = dialect_of(&open_api.openapi);
	let mut reader = Reader {
		doc: &doc,
		dialect,
		warnings: Vec::new(),
	};
	if dialect == Dialect::Oas30 {
		reader.warn(format!(
			"document declares OpenAPI {}: schemas translated from the 3.0 dialect to JSON Schema 2020-12 (nullable, exclusive bounds)",
			open_api.openapi
		));
	}
	let paths = doc
		.get("paths")
		.and_then(Value::as_object)
		.cloned()
		.unwrap_or_default();
	let mut tools = Vec::new();
	for (path, item) in &paths {
		let Some(item) = item.as_object() else {
			continue;
		};
		for method in HTTP_METHODS {
			let Some(op) = item.get(method).and_then(Value::as_object) else {
				continue;
			};
			let Some(name) = str_of(op.get("operationId")).map(String::from) else {
				reader.warn(format!(
					"{} {path} skipped: no operationId",
					method.to_uppercase()
				));
				continue;
			};
			let output = reader.lift_output_schema(op);
			let input = reader.lift_input_schema(item, op);
			let base_path = reader.base_path(item, op);

			let summary = str_of(op.get("summary"))
				.filter(|s| !s.is_empty())
				.map(String::from);
			let description = str_of(op.get("description"))
				.map(String::from)
				.or_else(|| summary.clone())
				.unwrap_or_else(|| name.clone());
			let mut tool = Tool::new_with_raw(
				Cow::Owned(name.clone()),
				Some(Cow::Owned(description)),
				Arc::new(input.schema),
			);
			if let Some(summary) = &summary {
				let end = std::cmp::min(64, summary.len());
				tool = tool.with_title(summary[..summary.floor_char_boundary(end)].to_string());
			}
			// MCP allows only object-typed output schemas; other shapes are not advertised.
			if let Some(output) = output
				&& output.get("type") == Some(&json!("object"))
			{
				tool.output_schema = Some(Arc::new(output));
			}
			let allowed_headers = input
				.parameters
				.iter()
				.filter(|p| p.location == ParameterLocation::Header)
				.map(|p| p.name.clone())
				.collect();
			let upstream = UpstreamOpenAPICall {
				method: method.to_uppercase(),
				path: path.clone(),
				allowed_headers,
				content_type: input.content_type,
				parameters: input.parameters,
				request_body: input.request_body,
				base_path,
			};
			tools.push((tool, upstream));
		}
	}
	Ok((tools, reader.warnings))
}

pub(crate) fn parse_openapi_schema(
	open_api: &OpenAPI,
) -> Result<Vec<(Tool, UpstreamOpenAPICall)>, ParseError> {
	let (tools, warnings) = parse_openapi_schema_with_warnings(open_api)?;
	for warning in warnings {
		warn!("openapi: {warning}");
	}
	Ok(tools)
}

/// Regex to match path template parameters like `{param_name}`.
static PATH_PARAM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{[^}]+\}").unwrap());

/// Characters that are safe in path segments (RFC 3986 unreserved characters).
/// All other characters will be percent-encoded to prevent path traversal/injection.
const PATH_SEGMENT_SAFE: &AsciiSet = &percent_encoding::NON_ALPHANUMERIC
	.remove(b'-')
	.remove(b'.')
	.remove(b'_')
	.remove(b'~');

fn substitute_path_params(
	template: &str,
	params: &serde_json::Map<String, Value>,
) -> Result<String, PathParamError> {
	let mut path = String::with_capacity(template.len());
	let mut last_end = 0;
	for placeholder in PATH_PARAM_RE.find_iter(template) {
		path.push_str(&template[last_end..placeholder.start()]);
		let matched = placeholder.as_str();
		// The regex guarantees ASCII braces at both ends
		let param = &matched[1..matched.len() - 1];
		match params.get(param) {
			Some(Value::Number(value)) => path.push_str(&value.to_string()),
			// `.` is unreserved so percent-encoding leaves dot segments intact; reject them per
			// decoded segment so upstreams that resolve `%2F` before the path still cannot traverse
			Some(Value::String(value))
				if value
					.split(['/', '\\'])
					.any(|segment| matches!(segment, "" | "." | "..")) =>
			{
				return Err(PathParamError::UnsafeSegment(param.to_string()));
			},
			Some(Value::String(value)) => path.extend(utf8_percent_encode(value, PATH_SEGMENT_SAFE)),
			Some(_) => return Err(PathParamError::UnsupportedType(param.to_string())),
			None => return Err(PathParamError::Missing(param.to_string())),
		}
		last_end = placeholder.end();
	}
	path.push_str(&template[last_end..]);

	Ok(path)
}

/// Normalizes URL path construction to avoid double slashes
/// Ensures exactly one slash between prefix and path components
pub(crate) fn normalize_url_path(prefix: &str, path: &str) -> String {
	let prefix = prefix.trim_end_matches('/');
	let path = if path.starts_with('/') {
		path
	} else {
		// If path doesn't start with '/', add one
		&format!("/{path}")
	};

	if prefix.is_empty() {
		path.to_string()
	} else {
		format!("{prefix}{path}")
	}
}

fn encode_query_value(value: &str) -> Cow<'_, str> {
	Cow::from(utf8_percent_encode(
		value,
		percent_encoding::NON_ALPHANUMERIC,
	))
}

#[derive(Debug)]
pub struct Handler {
	pub prefix: String,
	pub http_client: super::McpHttpClient,
	pub tools: Vec<(Tool, UpstreamOpenAPICall)>,
}

impl Handler {
	pub fn new(
		http_client: super::McpHttpClient,
		tools: Vec<(Tool, UpstreamOpenAPICall)>,
		prefix: String,
	) -> Self {
		Self {
			prefix,
			http_client,
			tools,
		}
	}

	pub fn get_session_state(&self) -> sessionpersistence::MCPSession {
		sessionpersistence::MCPSession {
			target_name: Some(self.http_client.target_name().to_string()),
			session: None,
			backend: self.http_client.pinned_backend(),
		}
	}

	pub fn set_session_id(&self, _: Option<&str>, pinned: Option<SocketAddr>) {
		if let Some(pinned) = pinned {
			self.http_client.pin_backend(ResolvedDestination(pinned));
		}
	}

	pub async fn send_message(
		&self,
		request: JsonRpcRequest<ClientRequest>,
		ctx: &IncomingRequestContext,
	) -> Result<mergestream::Messages, UpstreamError> {
		use rmcp::model::*;
		let method = request.request.method();
		let id = request.id;
		let res = match request.request {
			ClientRequest::InitializeRequest(_) => Messages::from_result(
				id,
				ServerConfig::new(ServerCapabilities::builder().enable_tools().build()),
			),
			ClientRequest::GetPromptRequest(_) => Messages::from_result(id, GetPromptResult::new(vec![])),
			ClientRequest::ListPromptsRequest(_) => Messages::from_result(
				id,
				ListPromptsResult {
					..Default::default()
				},
			),
			ClientRequest::ListResourcesRequest(_) => Messages::from_result(
				id,
				ListResourcesResult {
					..Default::default()
				},
			),
			ClientRequest::ListResourceTemplatesRequest(_) => Messages::from_result(
				id,
				ListResourceTemplatesResult {
					..Default::default()
				},
			),
			ClientRequest::DiscoverRequest(_) => Messages::from_result(
				id,
				DiscoverResult::new(
					ProtocolVersion::KNOWN_VERSIONS.to_vec(),
					ServerCapabilities::builder().enable_tools().build(),
				)
				.with_server_info(Implementation::new(
					"agentgateway",
					BuildInfo::new().version.to_string(),
				)),
			),
			ClientRequest::GetTaskRequest(r) => {
				return Err(UpstreamError::InvalidRequest(format!(
					"unknown task {}",
					r.params.task_id
				)));
			},
			ClientRequest::UpdateTaskRequest(r) => {
				return Err(UpstreamError::InvalidRequest(format!(
					"unknown task {}",
					r.params.task_id
				)));
			},
			ClientRequest::CancelTaskRequest(r) => {
				return Err(UpstreamError::InvalidRequest(format!(
					"unknown task {}",
					r.params.task_id
				)));
			},
			ClientRequest::ReadResourceRequest(_) => {
				Messages::from_result(id, ReadResourceResult::new(vec![]))
			},
			ClientRequest::PingRequest(_) => Messages::from_result(id, ServerResult::empty(())),
			ClientRequest::SubscriptionsListenRequest(_) => {
				Messages::from(ServerJsonRpcMessage::notification(
					ServerNotification::SubscriptionsAcknowledgedNotification(
						SubscriptionsAcknowledgedNotification::new(
							SubscriptionsAcknowledgedNotificationParams::new(SubscriptionFilter::new()),
						),
					),
				))
				.then_pending()
			},
			ClientRequest::CustomRequest(_)
			| ClientRequest::SetLevelRequest(_)
			| ClientRequest::SubscribeRequest(_)
			| ClientRequest::UnsubscribeRequest(_) => Messages::empty(),
			ClientRequest::CompleteRequest(_) => {
				return Err(UpstreamError::InvalidMethod(method.to_string()));
			},
			ClientRequest::CallToolRequest(ctr) => {
				let res = self
					.call_tool(ctr.params.name.as_ref(), ctr.params.arguments, ctx)
					.await?;
				Messages::from_result(id, res)
			},
			ClientRequest::ListToolsRequest(_) => Messages::from_result(
				id,
				ListToolsResult {
					tools: self.tools(),
					..Default::default()
				},
			),
			_ => return Err(UpstreamError::InvalidMethod(method.to_string())),
		};
		Ok(res)
	}

	/// The tool's arguments are one flat object, the shape its input schema advertises.
	/// Each declared parameter routes its property to the path template, the query string
	/// or the request headers; whatever no parameter claims is the JSON body, when the
	/// operation takes one. A cookie parameter is documented but never sent.
	pub async fn call_tool(
		&self,
		name: &str,
		args: Option<JsonObject>,
		ctx: &IncomingRequestContext,
	) -> Result<CallToolResult, UpstreamError> {
		let (_tool, info) = self
			.tools
			.iter()
			.find(|(t, _info)| t.name == name)
			.ok_or_else(|| anyhow::anyhow!("tool {} not found", name))?;

		let args = args.unwrap_or_default();

		// --- Parameter Extraction ---
		let mut path_params = JsonObject::new();
		let mut query_params = JsonObject::new();
		let mut header_params = JsonObject::new();
		let mut consumed: HashSet<&str> = HashSet::new();
		for p in &info.parameters {
			let Some(value) = args.get(&p.key) else {
				continue;
			};
			consumed.insert(p.key.as_str());
			match p.location {
				ParameterLocation::Path => {
					path_params.insert(p.name.clone(), value.clone());
				},
				// A null is an omitted value, not a value: it never travels.
				ParameterLocation::Query if !value.is_null() => {
					query_params.insert(p.name.clone(), value.clone());
				},
				ParameterLocation::Header if !value.is_null() => {
					header_params.insert(p.name.clone(), value.clone());
				},
				_ => {},
			}
		}
		let body_value: Option<Value> =
			if info.content_type.as_deref() == Some("application/octet-stream") {
				args.get("body").cloned()
			} else if info.request_body {
				Some(Value::Object(
					args
						.iter()
						.filter(|(k, _)| !consumed.contains(k.as_str()))
						.map(|(k, v)| (k.clone(), v.clone()))
						.collect(),
				))
			} else {
				None
			};

		// --- URL Construction ---
		// Substitute path parameters into the path template in a single pass
		let path = substitute_path_params(&info.path, &path_params)
			.map_err(|error| UpstreamError::InvalidRequest(error.to_string()))?;

		// Use normalize_url_path to avoid double slashes; an operation's own servers entry
		// takes precedence over the document's (the handler's prefix).
		let prefix = info.base_path.as_deref().unwrap_or(&self.prefix);
		let normalized_path = normalize_url_path(prefix, &path);
		let base_url = format!(
			"{}://{}{}",
			"http",
			self.http_client.backend().hostport(),
			normalized_path
		);

		// --- Request Building ---
		let method = Method::from_bytes(info.method.to_uppercase().as_bytes()).map_err(|e| {
			anyhow::anyhow!(
				"Invalid HTTP method '{}' for tool '{}': {}",
				info.method,
				name,
				e
			)
		})?;

		// Build query string
		let query_string = if query_params.is_empty() {
			String::new()
		} else {
			let format_pair = |param_name: &str, key: &str, v: &Value| -> Option<String> {
				match v {
					Value::Null => Some(key.to_string()),
					Value::Bool(b) => Some(format!("{key}={b}")),
					Value::Number(n) => Some(format!("{key}={n}")),
					Value::String(s) => Some(format!("{key}={}", encode_query_value(s))),
					_ => {
						warn!(
							"Query parameter '{}' for tool '{}' unsupported (value: {:?}), skipping",
							param_name, name, v
						);
						None
					},
				}
			};
			query_params
				.iter()
				.flat_map(|(k, v)| {
					let key = encode_query_value(k);
					match v {
						Value::Array(a) => a
							.iter()
							.filter_map(|v| format_pair(k, &key, v))
							.collect::<Vec<_>>(),
						_ => format_pair(k, &key, v).into_iter().collect(),
					}
				})
				.fold(String::new(), |mut acc, pair| {
					acc.push(if acc.is_empty() { '?' } else { '&' });
					acc.push_str(&pair);
					acc
				})
		};

		let uri = format!("{base_url}{query_string}");

		let mut rb = http::Request::builder()
			.method(method)
			.uri(uri)
			.header(ACCEPT, HeaderValue::from_static("application/json"));

		// Build request body
		let body = if let Some(body_val) = body_value {
			match info.content_type.as_deref() {
				Some("application/octet-stream") => {
					rb = rb.header(
						CONTENT_TYPE,
						HeaderValue::from_static("application/octet-stream"),
					);
					let s = body_val.as_str().unwrap_or_default();
					base64::engine::general_purpose::STANDARD
						.decode(s)
						.map_err(|e| UpstreamError::OpenAPIError(e.into()))?
				},
				_ => {
					rb = rb.header(CONTENT_TYPE, HeaderValue::from_static("application/json"));
					serde_json::to_vec(&body_val).map_err(|e| UpstreamError::OpenAPIError(e.into()))?
				},
			}
		} else {
			Vec::new()
		};

		// Build the final request
		let mut request = rb
			.body(body.into())
			.map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;

		ctx.apply(&mut request)?;

		// First header set wins including headers set by ctx.apply or the gateway
		for (key, value) in &header_params {
			// Only allow headers defined in the OpenAPI schema
			if !info.allowed_headers.contains(key) {
				debug!(
					"Ignoring header '{}' for tool '{}' not defined in schema",
					key, name
				);
				continue;
			}

			if let Some(s_val) = value.as_str() {
				match (
					HeaderName::from_bytes(key.as_bytes()),
					HeaderValue::from_str(s_val),
				) {
					(Ok(header_name), Ok(header_value)) => {
						// Ingore if header is protected
						if header_name == CONTENT_LENGTH
							|| header_name == CONTENT_TYPE
							|| header_name == TRANSFER_ENCODING
							|| header_name == HOST
						{
							debug!("Ignoring protected header '{}' for tool '{}'", key, name);
							continue;
						}

						// Don't override existing headers
						if request.headers().contains_key(&header_name) {
							debug!("Ingoring header '{}' for tool '{}' already set", key, name);
							continue;
						}

						request.headers_mut().insert(header_name, header_value);
					},
					(Err(_), _) => warn!(
						"Invalid header name '{}' for tool '{}', skipping",
						key, name
					),
					(_, Err(_)) => warn!(
						"Invalid header value '{}' for header '{}' in tool '{}', skipping",
						s_val, key, name
					),
				}
			} else {
				warn!(
					"Header parameter '{}' for tool '{}' is not a string (value: {:?}), skipping",
					key, name, value
				);
			}
		}

		let response = self.http_client.call(request).await?;

		// Read response body
		let status = response.status();

		// per https://modelcontextprotocol.io/specification/2025-11-25/server/tools
		// Clients MAY provide protocol errors to language models which are mainly caught up higher.
		// However we contend that server errors on the tool call should also count as protocol
		// errors. A client error (4xx) is the model's to see and act on: its content comes back
		// as a tool result with isError set, so the model learns what the service refused.
		if !status.is_server_error() {
			let lim = crate::http::response_buffer_limit(&response);
			let content_encoding = response.headers().typed_get::<headers::ContentEncoding>();
			let content_type = response
				.headers()
				.typed_get::<headers::ContentType>()
				.map(headers::Mime::from);
			let body_bytes = crate::http::compression::to_bytes_with_decompression(
				response.into_body(),
				content_encoding.as_ref(),
				lim,
			)
			.await
			.map_err(|e| UpstreamError::OpenAPIError(e.into()))?
			.1;

			let mut result = if let Some(mime) = content_type.filter(|m| m.type_() == "image") {
				let data = base64::engine::general_purpose::STANDARD.encode(&body_bytes);
				CallToolResult::success(vec![ContentBlock::image(data, mime.essence_str())])
			} else {
				let res = match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
					Ok(val @ (Value::Object(_) | Value::Null)) => val,
					Ok(data) => json!({ "data": data }),
					Err(_) => {
						// We should probably record a metric here as this means despite requesting json we got back non-json
						// This would be fine if it was a 5XX but its not so we help a little.
						json!({ "code": status.as_u16(), "message": String::from_utf8_lossy(&body_bytes) })
					},
				};

				// Serialize structured content to JSON string for backwards compatibility
				// Per MCP spec https://modelcontextprotocol.io/specification/2025-06-18/server/tools#structured-content:
				//   "a tool that returns structured content SHOULD also return the serialized JSON in a TextContent block"
				// Note: This part of the spec is in flux, see https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1624
				CallToolResult::structured(res)
			};
			if status.is_client_error() {
				result.is_error = Some(true);
			}
			Ok(result)
		} else {
			let lim = crate::http::response_buffer_limit(&response);
			let body = String::from_utf8(
				crate::http::read_body_with_limit(response.into_body(), lim)
					.await
					.map_err(|e| UpstreamError::OpenAPIError(e.into()))?
					.to_vec(),
			)
			.map_err(|e| UpstreamError::OpenAPIError(e.into()))?;
			Err(UpstreamError::OpenAPIError(anyhow::anyhow!(
				"Upstream API call for tool '{}' failed with status {}: {}",
				name,
				status,
				body
			)))
		}
	}

	pub fn tools(&self) -> Vec<Tool> {
		self.tools.clone().into_iter().map(|(t, _)| t).collect()
	}
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
