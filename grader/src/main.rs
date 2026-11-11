//! BlindBench sealed grader.
//!
//! Runs inside a TEE (OutLayer). It is given ONE item of a committed eval set
//! and ONE enclave-signed model call, encrypted so that only this program can
//! read them, and it answers four questions the set's owner would otherwise
//! have to be trusted on:
//!
//!   1. Which item is this?  It rebuilds the item's salted Merkle leaf. The
//!      caller checks that leaf against the root committed onchain.
//!   2. Was the committed question the one sent?  The request body must be a
//!      plain two-message chat: the fixed system line, then one user message,
//!      with no request field beyond the few the runner sends.
//!      The item is rebuilt around that user message, so the leaf in (1) only
//!      comes out right if the message is exactly the committed prompt.
//!   3. Which bytes went to and came from the model?  It hashes the request and
//!      response bodies. The caller checks those hashes against the model
//!      enclave's signature.
//!   4. What does the answer score?  Exact grading, the same rules as
//!      cli/lib/grade.mjs.
//!
//! Input (stdin, public): {"v":2,"nonce":"<24 hex>","ct":"<base64>"}
//!   ct = ChaCha20-Poly1305(INPUT_KEY, nonce, DEFLATE(plaintext)), INPUT_KEY is a
//!   secret only this program's hash can read.
//! Plaintext: {"salt":"<hex>","pre":"...","post":"...","request":"...","response":"..."}
//!   canonical item JSON = pre + JSON string of the prompt + post.
//! Output (stdout, public, under 900 bytes):
//!   {"v":1,"grader":"blindbench-exact/1","leaf","request_sha256","response_sha256","model","score","empty"}
//! Nothing about the question or the answer leaves except the score.

use base64::Engine;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use unicode_normalization::UnicodeNormalization;

pub const GRADER: &str = "blindbench-exact/1";
/// The system message every exact-graded item is asked with (cli/lib/grade.mjs).
pub const SYSTEM: &str = "You are being evaluated. Think as needed, then end your reply with one line: FINAL: <answer>";

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex::encode(h.finalize())
}

/// JSON.stringify of a string, byte for byte as JavaScript writes it.
pub fn js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The model's reply text from a response body: one JSON body, or a stream of
/// server-sent "data:" lines whose content deltas are joined.
pub fn reply_text(body: &str) -> Result<String, String> {
    if let Ok(j) = serde_json::from_str::<Value>(body) {
        if j.is_object() {
            return Ok(j["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string());
        }
    }
    let mut text = String::new();
    let mut seen = false;
    for line in body.split('\n') {
        let Some(data) = line.strip_prefix("data:") else { continue };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(j) = serde_json::from_str::<Value>(data) else { continue };
        seen = true;
        if let Some(s) = j["choices"][0]["delta"]["content"].as_str() {
            text.push_str(s);
        }
    }
    if seen {
        Ok(text)
    } else {
        Err("response body is neither JSON nor an event stream".into())
    }
}

// ---------- exact grading, the same rules as cli/lib/grade.mjs ----------

/// The answer line: what follows the last "FINAL:" (case-insensitive), else the last line.
pub fn extract_final(text: &str) -> String {
    let lower: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    let chars: Vec<char> = text.chars().collect();
    let pat: Vec<char> = "final:".chars().collect();
    let mut found: Option<String> = None;
    let mut i = 0;
    while i + pat.len() <= chars.len() {
        if lower[i..i + pat.len()] == pat[..] {
            // FINAL:\s*(.+) with the regex's backtracking: \s* is greedy but gives
            // characters back until (.+) can take at least one that is not a line end.
            let j0 = i + pat.len();
            let mut ws_end = j0;
            while ws_end < chars.len() && is_js_space(chars[ws_end]) {
                ws_end += 1;
            }
            let mut j = ws_end;
            let start = loop {
                if j < chars.len() && !is_line_end(chars[j]) {
                    break Some(j);
                }
                if j == j0 {
                    break None;
                }
                j -= 1;
            };
            if let Some(j) = start {
                let mut k = j;
                while k < chars.len() && !is_line_end(chars[k]) {
                    k += 1;
                }
                found = Some(chars[j..k].iter().collect::<String>());
                i = k;
                continue;
            }
        }
        i += 1;
    }
    match found {
        Some(s) => js_trim(&s).to_string(),
        None => js_trim(text).split('\n').last().unwrap_or("").to_string(),
    }
}
fn is_line_end(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}
/// JavaScript's \s and String.prototype.trim white space.
fn is_js_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_space)
}

/// A plain number, optionally with a currency sign, thousands commas, a unit
/// (%, x, bps, days) or accounting brackets for a negative. None otherwise.
pub fn as_number(s: &str) -> Option<f64> {
    let t: String = s.nfkc().filter(|c| *c != '*' && *c != '`').collect();
    let mut t = js_trim(&t).to_string();
    if t.ends_with('.') {
        t.pop();
    }
    let mut t = js_trim(&t).to_string();
    let mut neg = false;
    if t.starts_with('(') && t.ends_with(')') && t.chars().count() >= 2 && !t[1..t.len() - 1].contains('\n') {
        t = js_trim(&t[1..t.len() - 1]).to_string();
        neg = true;
    }
    let c: Vec<char> = t.chars().collect();
    let n = c.len();
    let mut i = 0;
    let skip_ws = |i: &mut usize| {
        while *i < n && is_js_space(c[*i]) {
            *i += 1;
        }
    };
    // (?:us)?\$?\s*([+\-−]?)\s*\$?\s*
    if i + 1 < n && c[i].to_ascii_lowercase() == 'u' && c[i + 1].to_ascii_lowercase() == 's' {
        i += 2;
    }
    if i < n && c[i] == '$' {
        i += 1;
    }
    skip_ws(&mut i);
    let mut minus = false;
    if i < n && matches!(c[i], '+' | '-' | '\u{2212}') {
        minus = c[i] != '+';
        i += 1;
    }
    skip_ws(&mut i);
    if i < n && c[i] == '$' {
        i += 1;
    }
    skip_ws(&mut i);
    // ((?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?|\.\d+)
    let digit = |x: char| x.is_ascii_digit();
    let start = i;
    let mut digits = String::new();
    let run = |from: usize| {
        let mut j = from;
        while j < n && digit(c[j]) {
            j += 1;
        }
        j
    };
    let int_end = run(i);
    if int_end > i {
        // \d{1,3}(?:,\d{3})+ first, as the regex tries it; otherwise the plain run of digits
        let mut j = int_end;
        if int_end - i <= 3 {
            let mut k = int_end;
            while k + 3 < n && c[k] == ',' && digit(c[k + 1]) && digit(c[k + 2]) && digit(c[k + 3]) {
                k += 4;
            }
            j = k;
        }
        digits.extend(c[i..j].iter().filter(|x| **x != ','));
        i = j;
        if i + 1 < n && c[i] == '.' && digit(c[i + 1]) {
            let e = run(i + 1);
            digits.extend(c[i..e].iter());
            i = e;
        }
    } else if i + 1 < n && c[i] == '.' && digit(c[i + 1]) {
        let e = run(i + 1);
        digits.extend(c[i..e].iter());
        i = e;
    }
    if i == start {
        return None;
    }
    skip_ws(&mut i);
    // (?:%|x|×|bps|basis points|days)?$   (case-insensitive)
    let rest: String = c[i..].iter().collect::<String>().to_lowercase();
    if !matches!(rest.as_str(), "" | "%" | "x" | "\u{d7}" | "bps" | "basis points" | "days") {
        return None;
    }
    let v: f64 = digits.parse().ok()?;
    Some(if minus != neg { -v } else { v })
}

/// Lower-case, NFKC, a leading minus kept as the word "minus", every other run
/// of non-letters and non-digits turned into one space.
pub fn norm(s: &str) -> String {
    let t: Vec<char> = s.to_lowercase().nfkc().collect();
    let word = |c: char| c.is_alphabetic() || c.is_numeric();
    let mut out = String::new();
    let mut gap = false;
    let mut i = 0;
    while i < t.len() {
        let c = t[i];
        if (c == '-' || c == '\u{2212}') && i + 1 < t.len() && t[i + 1].is_ascii_digit() && (i == 0 || !word(t[i - 1])) {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str("minus");
            gap = true;
        } else if word(c) {
            if gap && !out.is_empty() {
                out.push(' ');
            }
            gap = false;
            out.push(c);
        } else {
            gap = true;
        }
        i += 1;
    }
    out
}

/// 1 if the reply's answer line matches the key (numbers by value, sign matters), else 0.
pub fn grade_exact(item: &Value, text: &str) -> u8 {
    let raw = extract_final(text);
    let mut keys: Vec<String> = vec![value_text(&item["answer"])];
    if let Some(a) = item["accept"].as_array() {
        keys.extend(a.iter().map(value_text));
    }
    let got = as_number(&raw);
    let num_keys: Vec<f64> = keys.iter().filter_map(|k| as_number(k)).collect();
    let ok = match got {
        Some(g) if !num_keys.is_empty() => num_keys.iter().any(|v| (v - g).abs() <= 1e-9 * v.abs().max(1.0)),
        _ => keys.iter().any(|k| norm(k) == norm(&raw)),
    };
    ok as u8
}
/// String(x) for the JSON values an answer key holds.
fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

// ---------- one sealed grading job ----------
pub fn grade_job(plain: &Value) -> Result<Value, String> {
    let field = |k: &str| plain[k].as_str().ok_or_else(|| format!("missing {k}"));
    let (salt, pre, post, request, response) = (field("salt")?, field("pre")?, field("post")?, field("request")?, field("response")?);
    let salt = hex::decode(salt).map_err(|_| "salt is not hex")?;
    // A fixed salt length: otherwise bytes could be moved between the salt and the
    // item, and one committed leaf could be opened as two different items.
    if salt.len() != 32 {
        return Err("salt must be 32 bytes".into());
    }

    // 2. the request: a system message and the prompt, nothing else in the conversation
    let req: Value = serde_json::from_str(request).map_err(|_| "request body is not JSON")?;
    // The body must be exactly what a JSON writer produces from what was parsed: a
    // repeated key, which this parser and the model's server could read differently,
    // does not survive that.
    if serde_json::to_string(&req).ok().as_deref() != Some(request) {
        return Err("request body is not plain compact JSON".into());
    }
    check_request_fields(&req)?;
    let msgs = req["messages"].as_array().ok_or("request has no messages")?;
    let plain_msg = |m: &Value, role: &str| m.as_object().is_some_and(|o| o.len() == 2 && o.get("role").and_then(Value::as_str) == Some(role) && o.get("content").is_some_and(Value::is_string));
    if msgs.len() != 2 || !plain_msg(&msgs[0], "system") || msgs[0]["content"] != SYSTEM || !plain_msg(&msgs[1], "user") {
        return Err("request is not the plain system + user conversation".into());
    }
    let prompt = msgs[1]["content"].as_str().ok_or("the user message is not text")?;
    let model = req["model"].as_str().ok_or("request names no model")?;
    if model.is_empty() || model.len() > 128 {
        return Err("the model name is empty or too long".into());
    }

    // 1. the item: canonical JSON rebuilt around the prompt that was sent
    let canonical = format!("{pre}{}{post}", js_string(prompt));
    let item: Value = serde_json::from_str(&canonical).map_err(|_| "the item does not parse")?;
    if !item.is_object() || item["prompt"].as_str() != Some(prompt) {
        return Err("the prompt sent is not the item's prompt".into());
    }
    if item["answer"].is_null() {
        return Err("the item has no answer key".into());
    }
    let leaf = sha256_hex(&[&salt, canonical.as_bytes()]);

    // 3 and 4
    let text = reply_text(response)?;
    Ok(json!({
        "v": 1, "grader": GRADER, "leaf": leaf,
        "request_sha256": sha256_hex(&[request.as_bytes()]),
        "response_sha256": sha256_hex(&[response.as_bytes()]),
        "model": model, "score": grade_exact(&item, &text), "empty": js_trim(&text).is_empty(),
    }))
}

/// Only the request fields the runner sends are allowed. Anything else could steer
/// the model towards the answer (a forced choice, a grammar, a prefilled reply) or
/// change which conversation the server sees.
fn check_request_fields(req: &Value) -> Result<(), String> {
    let obj = req.as_object().ok_or("request body is not an object")?;
    for (k, v) in obj {
        let ok = match k.as_str() {
            "model" | "messages" => true,
            "max_tokens" => v.as_u64().is_some_and(|n| n > 0),
            "temperature" => v.as_f64().is_some_and(|t| (0.0..=2.0).contains(&t)),
            "stream" => v.is_boolean(),
            "stream_options" => v.as_object().is_some_and(|o| o.len() == 1 && o.get("include_usage") == Some(&Value::Bool(true))),
            // how much the model reasons, and nothing else about its chat template
            "chat_template_kwargs" => v.as_object().is_some_and(|o| {
                o.iter().all(|(k, v)| match k.as_str() {
                    "thinking" | "enable_thinking" => v.is_boolean(),
                    "reasoning_effort" => matches!(v.as_str(), Some("low" | "medium" | "high")),
                    _ => false,
                })
            }),
            _ => false,
        };
        if !ok {
            return Err(format!("request field not allowed: {}", k.chars().take(40).collect::<String>()));
        }
    }
    Ok(())
}

pub fn open(input: &Value, key_hex: &str) -> Result<Value, String> {
    let key = hex::decode(key_hex.trim()).map_err(|_| "INPUT_KEY is not hex")?;
    if key.len() != 32 {
        return Err("INPUT_KEY must be 32 bytes".into());
    }
    let nonce = hex::decode(input["nonce"].as_str().ok_or("missing nonce")?).map_err(|_| "nonce is not hex")?;
    if nonce.len() != 12 {
        return Err("nonce must be 12 bytes".into());
    }
    let ct = base64::engine::general_purpose::STANDARD.decode(input["ct"].as_str().ok_or("missing ct")?).map_err(|_| "ct is not base64")?;
    let plain = ChaCha20Poly1305::new(Key::from_slice(&key)).decrypt(Nonce::from_slice(&nonce), ct.as_ref()).map_err(|_| "cannot decrypt the input")?;
    // Jobs are raw DEFLATE inside the seal; the size cap stops a decompression bomb.
    if input["v"].as_u64() != Some(2) {
        return Err("unknown input version".into());
    }
    let plain = miniz_oxide::inflate::decompress_to_vec_with_limit(&plain, 16 << 20).map_err(|_| "cannot decompress the input")?;
    serde_json::from_slice(&plain).map_err(|_| "the decrypted input is not JSON".into())
}

fn run() -> Result<Value, String> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let input: Value = serde_json::from_str(&raw).map_err(|_| "input is not JSON")?;
    // There is one way in: a sealed job. No plaintext mode exists, in tests or anywhere.
    let key = std::env::var("INPUT_KEY").map_err(|_| "INPUT_KEY is not set")?;
    grade_job(&open(&input, &key)?)
}

fn main() {
    let out = run().unwrap_or_else(|e| json!({ "v": 1, "grader": GRADER, "error": e }));
    print!("{out}");
    std::io::stdout().flush().ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors written by cli/scripts/grader-vectors.mjs from the JavaScript grader:
    /// both graders must agree on every one.
    #[test]
    fn agrees_with_the_javascript_grader() {
        let v: Value = serde_json::from_str(include_str!("../vectors.json")).unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() > 500);
        for c in cases {
            let text = c["text"].as_str().unwrap();
            assert_eq!(extract_final(text), c["final"].as_str().unwrap(), "final of {text:?}");
            let n = as_number(&extract_final(text));
            match c["number"].as_f64() {
                Some(x) => assert!(n.is_some() && (n.unwrap() - x).abs() <= 1e-12 * x.abs().max(1.0), "number of {text:?}: {n:?} vs {x}"),
                None => assert!(n.is_none(), "number of {text:?}: {n:?} should be none"),
            }
            assert_eq!(norm(&extract_final(text)), c["norm"].as_str().unwrap(), "norm of {text:?}");
            assert_eq!(grade_exact(&c["item"], text) as u64, c["score"].as_u64().unwrap(), "score of {text:?} against {}", c["item"]);
        }
        for s in v["strings"].as_array().unwrap() {
            assert_eq!(js_string(s["s"].as_str().unwrap()), s["json"].as_str().unwrap());
        }
    }
}
