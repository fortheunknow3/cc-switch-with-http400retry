//! Opt-in structural diagnostics. Never serialize request content, tool arguments,
//! schemas, arbitrary field names, headers, or upstream error messages into logs.

use super::{error_mapper::map_proxy_error_to_status, ProxyError};
use http::HeaderMap;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

fn fingerprint(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))[..16].to_string()
}

fn identifier(value: Option<&str>, secrets: &[String]) -> Option<String> {
    value.map(|text| {
        let text = crate::redact_known_secrets_strict(text, secrets);
        if text.len() > 160 {
            "[long-identifier]".to_string()
        } else if text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/[]:".contains(c))
        {
            text
        } else {
            "[non-identifier]".to_string()
        }
    })
}

fn value_kind(value: Option<&Value>) -> &'static str {
    match value {
        None => "absent",
        Some(Value::Null) => "null",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
        Some(Value::Number(_)) => "number",
        Some(Value::Bool(_)) => "boolean",
    }
}

fn safe_kind(value: Option<&str>) -> &'static str {
    match value {
        Some("message") => "message",
        Some("function_call") => "function_call",
        Some("function_call_output") => "function_call_output",
        Some("reasoning") => "reasoning",
        Some("web_search_call") => "web_search_call",
        Some("custom_tool_call") => "custom_tool_call",
        Some("custom_tool_call_output") => "custom_tool_call_output",
        Some("input_text") => "input_text",
        Some("output_text") => "output_text",
        Some("input_image") => "input_image",
        Some("input_file") => "input_file",
        Some("text") => "text",
        Some("thinking") => "thinking",
        Some("redacted_thinking") => "redacted_thinking",
        Some("tool_use") => "tool_use",
        Some("tool_result") => "tool_result",
        _ => "other",
    }
}

fn count(map: &mut BTreeMap<&'static str, usize>, key: &'static str) {
    *map.entry(key).or_default() += 1;
}

fn call_id(item: &Value) -> Option<&str> {
    item.get("call_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

// Object key order is not meaningful; array order is. Keep canonical hashes
// separate from body_hash, which fingerprints the actual serialized wire bytes.
fn canonical_bytes(value: &Value) -> Vec<u8> {
    fn write(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::Object(object) => {
                let mut entries: Vec<_> = object.iter().collect();
                entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
                out.push(b'{');
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key).expect("JSON string to Vec");
                    out.push(b':');
                    write(value, out);
                }
                out.push(b'}');
            }
            Value::Array(array) => {
                out.push(b'[');
                for (index, value) in array.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    write(value, out);
                }
                out.push(b']');
            }
            _ => serde_json::to_writer(out, value).expect("JSON scalar to Vec"),
        }
    }
    let mut bytes = Vec::new();
    write(value, &mut bytes);
    bytes
}

fn field_fingerprint(value: &Value) -> Value {
    let bytes = canonical_bytes(value);
    json!({"kind": value_kind(Some(value)), "bytes": bytes.len(), "hash": fingerprint(&bytes)})
}

fn safe_role(value: Option<&str>) -> Option<&'static str> {
    value.map(|role| match role {
        "user" => "user",
        "assistant" => "assistant",
        "system" => "system",
        "developer" => "developer",
        _ => "other",
    })
}

fn input_structure(outbound: &Value) -> Value {
    const TAIL_LIMIT: usize = 12;
    let Some(input) = outbound.get("input").and_then(Value::as_array) else {
        return json!({"prefix_stride": 64, "prefix_hashes": [], "tail": []});
    };
    let mut call_indices = HashMap::new();
    let mut output_indices = HashMap::new();
    for (index, item) in input.iter().enumerate() {
        let Some(id) = call_id(item) else { continue };
        match item.get("type").and_then(Value::as_str) {
            Some("function_call" | "custom_tool_call") => {
                call_indices.entry(id).or_insert(index);
            }
            Some("function_call_output" | "custom_tool_call_output") => {
                output_indices.entry(id).or_insert(index);
            }
            _ => {}
        }
    }
    let declared_names: HashSet<_> = outbound
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect();
    // A stable power-of-two stride keeps nearby requests comparable and limits
    // prefix samples to at most 48 regular boundaries plus the last 12 items.
    let stride = input.len().div_ceil(48).next_power_of_two().max(64);
    let tail_start = input.len().saturating_sub(TAIL_LIMIT);
    let mut prefixes = Vec::new();
    let mut tail = Vec::new();
    let mut prefix = Sha256::new();
    prefix.update(b"cc-switch-input-prefix-v1\0");
    for (index, item) in input.iter().enumerate() {
        let bytes = canonical_bytes(item);
        prefix.update((bytes.len() as u64).to_be_bytes());
        prefix.update(&bytes);
        if (index + 1) % stride == 0 || index >= tail_start {
            prefixes.push(json!({
                "end": index + 1,
                "hash": format!("{:x}", prefix.clone().finalize())[..16].to_string(),
            }));
        }
        if index < tail_start {
            continue;
        }
        let kind = item
            .get("type")
            .and_then(Value::as_str)
            .or_else(|| item.get("role").map(|_| "message"));
        let mut parts = BTreeMap::new();
        let content = item.get("content");
        for part in content.and_then(Value::as_array).into_iter().flatten() {
            count(
                &mut parts,
                safe_kind(part.get("type").and_then(Value::as_str)),
            );
        }
        let mut summary = json!({
            "index": index, "type": safe_kind(kind),
            "role": safe_role(item.get("role").and_then(Value::as_str)),
            "bytes": bytes.len(), "hash": fingerprint(&bytes),
            "content_kind": value_kind(content), "content_types": parts,
        });
        if let Some(value) = content {
            summary["content"] = field_fingerprint(value);
        }
        if matches!(
            kind,
            Some(
                "function_call"
                    | "function_call_output"
                    | "custom_tool_call"
                    | "custom_tool_call_output"
            )
        ) {
            summary["call_id_ref"] = json!(call_id(item).map(|id| fingerprint(id.as_bytes())));
            summary["call_index"] = json!(call_id(item).and_then(|id| call_indices.get(id)));
            summary["output_index"] = json!(call_id(item).and_then(|id| output_indices.get(id)));
        }
        if matches!(kind, Some("function_call" | "custom_tool_call")) {
            let name = item.get("name").and_then(Value::as_str);
            summary["name_ref"] = json!(name.map(|name| fingerprint(name.as_bytes())));
            // Historical functions may no longer be declared. This is context,
            // not an assertion that the request violates the upstream contract.
            summary["currently_declared"] = json!(name.map(|name| declared_names.contains(name)));
        }
        for field in ["arguments", "output", "summary", "encrypted_content"] {
            if let Some(value) = item.get(field) {
                summary[field] = field_fingerprint(value);
            }
        }
        tail.push(summary);
    }
    json!({"prefix_stride": stride, "prefix_hashes": prefixes, "tail": tail})
}

fn tool_structure(outbound: &Value) -> Value {
    const TOOL_LIMIT: usize = 64;
    let tools = outbound.get("tools").and_then(Value::as_array);
    let entries: Vec<_> = tools.into_iter().flatten().take(TOOL_LIMIT).enumerate().map(|(index, tool)| {
        let kind = match tool.get("type").and_then(Value::as_str).unwrap_or("") {
            "function" => "function",
            "custom" => "custom",
            "web_search" => "web_search",
            "web_search_preview" => "web_search_preview",
            "local_shell" => "local_shell",
            "mcp" => "mcp",
            _ => "other",
        };
        let mut summary = json!({
            "index": index, "type": kind,
            "name_ref": tool.get("name").and_then(Value::as_str).map(|name| fingerprint(name.as_bytes())),
            "definition": field_fingerprint(tool),
            "strict": tool.get("strict").and_then(Value::as_bool),
        });
        if let Some(parameters) = tool.get("parameters") {
            summary["parameters"] = field_fingerprint(parameters);
        }
        summary
    }).collect();
    json!({"entries": entries, "omitted": tools.map_or(0, Vec::len).saturating_sub(TOOL_LIMIT)})
}

pub(crate) fn summarize_request(
    original: &Value,
    outbound: &Value,
    bytes: &[u8],
    provider_id: &str,
    session_id: &str,
    secrets: &[String],
) -> Value {
    let mut original_blocks = BTreeMap::new();
    let messages = original.get("messages").and_then(Value::as_array);
    for message in messages.into_iter().flatten() {
        for block in message
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            count(
                &mut original_blocks,
                safe_kind(block.get("type").and_then(Value::as_str)),
            );
        }
    }

    let mut item_types = BTreeMap::new();
    let mut content_types = BTreeMap::new();
    let mut output_types = BTreeMap::new();
    let mut calls = HashSet::new();
    let mut outputs = HashSet::new();
    let mut reasoning_ids = HashSet::new();
    let mut duplicate_calls = 0usize;
    let mut duplicate_outputs = 0usize;
    let mut orphan_outputs = 0usize;
    let mut invalid_ids = 0usize;
    let mut invalid_arguments = 0usize;
    let mut non_object_arguments = 0usize;
    let mut unchecked_large_arguments = 0usize;
    let mut duplicate_reasoning_ids = 0usize;
    let mut encrypted_reasoning = 0usize;
    let mut text_bytes = 0usize;
    let mut argument_bytes = 0usize;
    let mut output_bytes = 0usize;
    let input = outbound.get("input").and_then(Value::as_array);
    for item in input.into_iter().flatten() {
        let kind = item
            .get("type")
            .and_then(Value::as_str)
            .or_else(|| item.get("role").map(|_| "message"));
        count(&mut item_types, safe_kind(kind));
        for part in item
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            count(
                &mut content_types,
                safe_kind(part.get("type").and_then(Value::as_str)),
            );
            text_bytes += part.get("text").and_then(Value::as_str).map_or(0, str::len);
        }
        match kind {
            Some("function_call" | "custom_tool_call") => {
                if let Some(id) = call_id(item) {
                    if !calls.insert(id) {
                        duplicate_calls += 1;
                    }
                } else {
                    invalid_ids += 1;
                }
                if kind == Some("function_call") {
                    argument_bytes += item
                        .get("arguments")
                        .and_then(Value::as_str)
                        .map_or(0, str::len);
                    match item.get("arguments").and_then(Value::as_str) {
                        Some(raw) if raw.len() > 1024 * 1024 => unchecked_large_arguments += 1,
                        Some(raw) => match serde_json::from_str::<Value>(raw) {
                            Ok(Value::Object(_)) => {}
                            Ok(_) => non_object_arguments += 1,
                            Err(_) => invalid_arguments += 1,
                        },
                        None => invalid_arguments += 1,
                    }
                }
            }
            Some("function_call_output" | "custom_tool_call_output") => {
                count(&mut output_types, value_kind(item.get("output")));
                output_bytes += match item.get("output") {
                    Some(Value::String(text)) => text.len(),
                    Some(value) => serde_json::to_vec(value).map_or(0, |bytes| bytes.len()),
                    None => 0,
                };
                if let Some(id) = call_id(item) {
                    if !calls.contains(id) {
                        orphan_outputs += 1;
                    }
                    if !outputs.insert(id) {
                        duplicate_outputs += 1;
                    }
                } else {
                    invalid_ids += 1;
                }
            }
            Some("reasoning") => {
                if let Some(id) = item.get("id").and_then(Value::as_str) {
                    if !reasoning_ids.insert(id) {
                        duplicate_reasoning_ids += 1;
                    }
                }
                if item
                    .get("encrypted_content")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
                {
                    encrypted_reasoning += 1;
                }
            }
            _ => {}
        }
    }
    let known_fields = [
        "model",
        "input",
        "instructions",
        "max_output_tokens",
        "temperature",
        "top_p",
        "stream",
        "reasoning",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "include",
        "prompt_cache_key",
        "store",
        "service_tier",
        "text",
        "metadata",
        "truncation",
        "previous_response_id",
    ];
    let fields: Vec<&str> = known_fields
        .iter()
        .copied()
        .filter(|key| outbound.get(*key).is_some())
        .collect();
    let unknown_fields = outbound.as_object().map_or(0, |obj| {
        obj.keys()
            .filter(|key| !known_fields.contains(&key.as_str()))
            .count()
    });
    let effort = match outbound
        .pointer("/reasoning/effort")
        .and_then(Value::as_str)
    {
        Some(v @ ("none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max")) => Some(v),
        Some(_) => Some("other"),
        None => None,
    };
    let components: BTreeMap<_, _> = known_fields
        .iter()
        .filter_map(|field| {
            outbound
                .get(*field)
                .map(|value| (*field, field_fingerprint(value)))
        })
        .collect();
    let mut summary = json!({
        "format": "openai_responses",
        "provider_ref": fingerprint(provider_id.as_bytes()),
        "session_ref": fingerprint(session_id.as_bytes()),
        "request_model": identifier(original.get("model").and_then(Value::as_str), secrets),
        "outbound_model": identifier(outbound.get("model").and_then(Value::as_str), secrets),
        "body_bytes": bytes.len(),
        "body_hash": fingerprint(bytes),
        "fields": fields,
        "unknown_field_count": unknown_fields,
        "original_message_count": messages.map_or(0, Vec::len),
        "original_block_counts": original_blocks,
        "input_count": input.map_or(0, Vec::len),
        "input_kind": value_kind(outbound.get("input")),
        "input_types": item_types,
        "content_types": content_types,
        "input_text_bytes": text_bytes,
        "tool_arguments_bytes": argument_bytes,
        "tool_output_bytes": output_bytes,
        "instructions_bytes": outbound.get("instructions").and_then(Value::as_str).map_or(0, str::len),
        "tool_count": outbound.get("tools").and_then(Value::as_array).map_or(0, Vec::len),
        "max_tokens": original.get("max_tokens").and_then(Value::as_u64),
        "max_output_tokens": outbound.get("max_output_tokens").and_then(Value::as_u64),
        "max_output_tokens_kind": value_kind(outbound.get("max_output_tokens")),
        "temperature": outbound.get("temperature").and_then(Value::as_f64),
        "top_p": outbound.get("top_p").and_then(Value::as_f64),
        "reasoning_effort": effort,
        "stream": outbound.get("stream").and_then(Value::as_bool),
        "store": outbound.get("store").and_then(Value::as_bool),
        "has_prompt_cache_key": outbound.get("prompt_cache_key").is_some(),
        "tool_output_types": output_types,
        "orphan_tool_outputs": orphan_outputs,
        "pending_tool_calls": calls.difference(&outputs).count(),
        "duplicate_call_ids": duplicate_calls,
        "duplicate_tool_outputs": duplicate_outputs,
        "invalid_call_ids": invalid_ids,
        "invalid_arguments_json": invalid_arguments,
        "non_object_arguments": non_object_arguments,
        "unchecked_large_arguments": unchecked_large_arguments,
        "encrypted_reasoning_items": encrypted_reasoning,
        "duplicate_reasoning_ids": duplicate_reasoning_ids,
    });
    summary["diagnostics_version"] = json!(2);
    summary["fingerprint_algorithm"] = json!("sha256-canonical-json-v1");
    summary["components"] = json!(components);
    summary["input_structure"] = input_structure(outbound);
    summary["tool_structure"] = tool_structure(outbound);
    summary
}

pub(crate) fn response_headers(status: u16, headers: &HeaderMap, secrets: &[String]) -> Value {
    let mut result = json!({"upstream_status": status});
    for name in ["x-request-id", "request-id", "x-trace-id", "traceparent"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            result[name] = json!(identifier(Some(value), secrets));
        }
    }
    result
}

pub(crate) fn response_outcome(
    headers: Option<Value>,
    error: Option<&ProxyError>,
    elapsed_ms: u64,
    secrets: &[String],
) -> Value {
    let mut result = headers.unwrap_or_else(|| json!({"upstream_status": null}));
    result["elapsed_ms"] = json!(elapsed_ms);
    result["outcome_status"] = json!(error.map_or_else(
        || result["upstream_status"].as_u64().unwrap_or(200) as u16,
        map_proxy_error_to_status,
    ));
    result["outcome"] = json!(if error.is_some() { "error" } else { "success" });
    if let Some(ProxyError::UpstreamError {
        body: Some(body), ..
    }) = error
    {
        static TRACE_ID: OnceLock<Regex> = OnceLock::new();
        let pattern = TRACE_ID.get_or_init(|| {
            Regex::new(r#"(?i)\btrace[_ -]?id["\\]*\s*[:=]\s*["\\]*([0-9a-f][0-9a-f-]{15,63})\b"#)
                .expect("constant trace ID regex")
        });
        result["error_body_bytes"] = json!(body.len());
        if let Some(found) = pattern.captures(body).and_then(|m| m.get(1)) {
            result["body_trace_id"] = json!(identifier(Some(found.as_str()), secrets));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summarize(body: &Value) -> Value {
        summarize_request(
            &json!({}),
            body,
            &serde_json::to_vec(body).unwrap(),
            "p",
            "s",
            &[],
        )
    }

    #[test]
    fn component_hashes_locate_equal_length_edits_and_ignore_object_key_order() {
        let a: Value = serde_json::from_str(r#"{"instructions":"alpha","input":[{"role":"user","content":"hello"}],"tools":[{"type":"function","name":"echo","parameters":{"type":"object","properties":{"text":{"type":"string"}}}}]}"#).unwrap();
        let reordered: Value = serde_json::from_str(r#"{"tools":[{"parameters":{"properties":{"text":{"type":"string"}},"type":"object"},"name":"echo","type":"function"}],"input":[{"content":"hello","role":"user"}],"instructions":"alpha"}"#).unwrap();
        assert_eq!(
            summarize(&a)["components"],
            summarize(&reordered)["components"]
        );

        let mut changed = a.clone();
        changed["instructions"] = json!("bravo");
        changed["tools"][0]["parameters"]["properties"]["text"]["type"] = json!("number");
        let old = summarize(&a);
        let new = summarize(&changed);
        assert_eq!(
            old["components"]["instructions"]["bytes"],
            new["components"]["instructions"]["bytes"]
        );
        for field in ["instructions", "tools"] {
            assert_ne!(
                old["components"][field]["hash"],
                new["components"][field]["hash"]
            );
        }
        assert_eq!(old["components"]["input"], new["components"]["input"]);
        assert_ne!(
            old["tool_structure"]["entries"][0]["parameters"]["hash"],
            new["tool_structure"]["entries"][0]["parameters"]["hash"]
        );
        changed["text"] = Value::Null;
        let new = summarize(&changed);
        assert!(old["components"].get("text").is_none());
        assert_eq!(new["components"]["text"]["kind"], "null");
    }

    #[test]
    fn prefix_hashes_distinguish_append_only_changes_from_edits_inside_history() {
        let input: Vec<_> = (0..1750)
            .map(|index| json!({"role":"user","content":format!("message {index}")}))
            .collect();
        let body = json!({"input":input});
        let old = summarize(&body);
        let mut appended = body.clone();
        appended["input"].as_array_mut().unwrap().extend([
            json!({"role":"assistant","content":"checking"}),
            json!({"type":"function_call","call_id":"call_x","name":"echo","arguments":"{}"}),
            json!({"type":"function_call_output","call_id":"call_x","output":"OK"}),
        ]);
        let new = summarize(&appended);
        let at = |summary: &Value, end: u64| -> Value {
            summary["input_structure"]["prefix_hashes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["end"] == end)
                .unwrap()["hash"]
                .clone()
        };
        assert_eq!(at(&old, 1750), at(&new, 1750));
        assert_eq!(new["input_structure"]["tail"].as_array().unwrap().len(), 12);
        appended["input"][500]["content"] = json!("edited history");
        let edited = summarize(&appended);
        assert_eq!(at(&new, 448), at(&edited, 448));
        assert_ne!(at(&new, 512), at(&edited, 512));
        // The tail itself is identical; prefix hashes still reveal the old edit.
        assert_eq!(
            new["input_structure"]["tail"],
            edited["input_structure"]["tail"]
        );
        assert_ne!(at(&new, 1750), at(&edited, 1750));
        let mut reordered = body;
        reordered["input"].as_array_mut().unwrap().swap(0, 1);
        assert_ne!(
            old["components"]["input"],
            summarize(&reordered)["components"]["input"]
        );
    }

    #[test]
    fn tail_pairs_calls_outside_the_window_and_never_exposes_roles_names_or_ids() {
        let mut input = vec![
            json!({"type":"function_call","call_id":"private-id","name":"private-tool","arguments":"{\"private-key\":\"private-value\"}"}),
        ];
        input.extend((0..30).map(|_| json!({"role":"private-role","content":[{"type":"private-type","text":"private text"}]})));
        input.push(
            json!({"type":"function_call_output","call_id":"private-id","output":"private output"}),
        );
        let summary = summarize(
            &json!({"input":input,"tools":[{"type":"function","name":"private-tool","parameters":{"private-key":"private schema"}}]}),
        );
        let output = summary["input_structure"]["tail"]
            .as_array()
            .unwrap()
            .last()
            .unwrap();
        assert_eq!(output["index"], 31);
        assert_eq!(output["call_index"], 0);
        assert_eq!(output["output_index"], 31);
        assert_eq!(output["call_id_ref"], fingerprint(b"private-id"));
        assert_eq!(summary["input_structure"]["tail"][0]["role"], "other");
        assert!(!summary.to_string().contains("private"));
        let pair = summarize(&json!({"input":[
            {"type":"function_call","call_id":"private-id","name":"private-tool","arguments":"{}"},
            {"type":"function_call_output","call_id":"private-id","output":"OK"}
        ],"tools":[{"type":"function","name":"private-tool"}]}));
        assert_eq!(
            pair["input_structure"]["tail"][0]["currently_declared"],
            true
        );
        assert_eq!(pair["input_structure"]["tail"][0]["output_index"], 1);
    }

    #[test]
    fn diagnostic_details_are_bounded_for_large_histories_and_tool_lists() {
        let body = json!({
            "input": vec![json!({"role":"user","content":"private conversation"}); 4096],
            "tools": vec![json!({"type":"private-type","name":"private-tool","parameters":{"description":"private schema"}}); 100]
        });
        let summary = summarize(&body);
        assert!(
            summary["input_structure"]["prefix_hashes"]
                .as_array()
                .unwrap()
                .len()
                <= 60
        );
        assert_eq!(
            summary["input_structure"]["tail"].as_array().unwrap().len(),
            12
        );
        assert_eq!(
            summary["tool_structure"]["entries"]
                .as_array()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(summary["tool_structure"]["omitted"], 36);
        assert!(summary.to_string().len() < 64 * 1024);
        assert!(!summary.to_string().contains("private"));
        for input in [
            json!(null),
            json!("private input"),
            json!({"private-key":"private value"}),
        ] {
            let summary = summarize(&json!({"input":input}));
            assert_eq!(summary["input_structure"]["tail"], json!([]));
            assert!(!summary.to_string().contains("private"));
        }
    }

    #[test]
    fn structural_summary_never_contains_content_arguments_or_credentials() {
        let secret = "sk-private-test-key".to_string();
        let original = json!({"model":"claude-opus-5[1M]","max_tokens":64000,"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"private reasoning","signature":"private signature"}]}]});
        let body = json!({
            "model": format!("vendor/{secret}"), "instructions":"private system prompt", "max_output_tokens":64000,
            "temperature": secret, "reasoning":{"effort":"private effort"},
            "prompt_cache_key":"private cache key", "private field name":"private value",
            "tools":[{"type":"function","name":"private-tool-name","parameters":{"private_schema_key":{"description":"private description"}}}],
            "input":[
                {"type":"message","role":"user","content":[{"type":"input_text","text":"private conversation"},{"type":"private block type","text":"private other text"}]},
                {"type":"function_call","call_id":"private-call-id","name":"private-tool-name","arguments":"{\"arg\":\"private tool arguments\"}"},
                {"type":"function_call_output","call_id":"private-call-id","output":"private tool result"},
                {"type":"reasoning","id":"private-reasoning-id","encrypted_content":"private encrypted state","summary":[{"text":"private summary"}]}
            ]
        });
        let encoded = serde_json::to_vec(&body).unwrap();
        let summary = summarize_request(
            &original,
            &body,
            &encoded,
            "private-provider",
            "private-session",
            &[secret.clone()],
        );
        let text = summary.to_string();
        for forbidden in [
            secret.as_str(),
            "private",
            "private field name",
            "private block type",
            "private_schema_key",
        ] {
            assert!(!text.contains(forbidden), "leaked {forbidden}");
        }
        assert_eq!(summary["outbound_model"], "vendor/[REDACTED]");
        assert_eq!(summary["max_output_tokens"], 64000);
        assert_eq!(summary["original_block_counts"]["thinking"], 1);
        assert_eq!(summary["input_types"]["reasoning"], 1);
        assert_eq!(summary["pending_tool_calls"], 0);
        assert_eq!(summary["body_bytes"], encoded.len());
    }

    #[test]
    fn summary_detects_tool_chain_and_argument_anomalies_without_exposing_ids() {
        let body = json!({"input":[
            {"type":"function_call_output","call_id":"orphan-secret-id","output":[]},
            {"type":"function_call","call_id":"duplicate-secret-id","arguments":"bad json"},
            {"type":"function_call","call_id":"duplicate-secret-id","arguments":"[]"},
            {"type":"function_call","arguments":"{}"},
            {"type":"function_call_output","call_id":"orphan-secret-id","output":"some result"}
        ]});
        let summary = summarize_request(&json!({}), &body, b"{}", "p", "s", &[]);
        assert_eq!(summary["orphan_tool_outputs"], 2);
        assert_eq!(summary["duplicate_call_ids"], 1);
        assert_eq!(summary["duplicate_tool_outputs"], 1);
        assert_eq!(summary["invalid_call_ids"], 1);
        assert_eq!(summary["pending_tool_calls"], 1);
        assert_eq!(summary["invalid_arguments_json"], 1);
        assert_eq!(summary["non_object_arguments"], 1);
        assert!(!summary.to_string().contains("secret-id"));
    }

    #[test]
    fn outcome_extracts_nested_trace_id_without_logging_error_text_or_headers() {
        let secret = "sk-private-test-key".to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer sk-private-test-key".parse().unwrap(),
        );
        headers.insert("x-request-id", "req_123456".parse().unwrap());
        let error = ProxyError::UpstreamError { status: 400, body: Some(json!({"error":{"message":format!("private rejected arguments {secret}; trace_id: b9512282a39ae61eb0a2f14a36d5820e")}}).to_string()) };
        let result = response_outcome(
            Some(response_headers(400, &headers, &[secret.clone()])),
            Some(&error),
            123,
            &[secret.clone()],
        );
        assert_eq!(result["body_trace_id"], "b9512282a39ae61eb0a2f14a36d5820e");
        assert_eq!(result["x-request-id"], "req_123456");
        assert_eq!(result["outcome_status"], 400);
        assert!(!result.to_string().contains("private"));
        assert!(!result.to_string().contains("authorization"));
    }

    #[test]
    fn fingerprints_support_comparison_and_hostile_identifiers_are_bounded() {
        let body = json!({"model":"x\nAuthorization: secret", "input":"a private input string"});
        let a = summarize_request(&json!({}), &body, b"same bytes", "p", "s", &[]);
        let b = summarize_request(&json!({}), &body, b"same bytes", "p", "s", &[]);
        let c = summarize_request(&json!({}), &body, b"changed bytes", "p", "s", &[]);
        assert_eq!(a["body_hash"], b["body_hash"]);
        assert_ne!(a["body_hash"], c["body_hash"]);
        assert_eq!(a["outbound_model"], "[non-identifier]");
        assert_eq!(a["input_kind"], "string");
        let error = ProxyError::Timeout("private network message".into());
        let result = response_outcome(None, Some(&error), 42, &[]);
        assert_eq!(result["upstream_status"], Value::Null);
        assert_eq!(result["outcome_status"], 504);
        assert!(!result.to_string().contains("private"));
    }
}
