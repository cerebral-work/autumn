//! Turso / libSQL HTTP `/v2/pipeline` [`ReplicaDestination`] for continuous
//! `SQLite` replication.
//!
//! Stores replicated WAL segments and compressed base snapshots in a remote
//! Turso database table (`autumn_replica_objects`) over Turso's Hrana
//! `/v2/pipeline` HTTP API using `reqwest::blocking`.
//!
//! # Credential safety
//!
//! Credentials arrive already resolved from the environment variable named by
//! `[replication.turso] auth_token_env` (never inlined into config).
//! [`TursoCredentials`] redacts `auth_token` in [`fmt::Debug`], and URLs
//! carrying userinfo or query parameters are refused at construction time.

#![cfg_attr(not(test), deny(clippy::disallowed_methods))]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::arithmetic_side_effects,
    )
)]

use std::fmt;
use std::io::Read as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;

use super::destination::{DestinationError, ReplicaDestination, validate_key};

/// Connect-phase timeout for Turso `/v2/pipeline` requests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-request timeout for Turso `/v2/pipeline` requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum response body size read from the Turso `/v2/pipeline` endpoint.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum single object size stored in a Turso replica row (128 MiB).
const MAX_OBJECT_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum provider error code / detail length kept in [`DestinationError`].
const MAX_ERROR_CODE_LEN: usize = 64;

/// Resolved Turso authentication credentials. Never formatted in cleartext.
#[derive(Clone)]
pub struct TursoCredentials {
    /// Bearer authentication token for Turso `/v2/pipeline`.
    pub auth_token: String,
}

impl fmt::Debug for TursoCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TursoCredentials")
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

/// Connection settings for [`TursoDestination`].
#[derive(Debug, Clone)]
pub struct TursoSettings {
    /// Target Turso database URL (`libsql://...`, `turso://...`, or `https://...`).
    pub url: String,
}

/// A Turso / libSQL `/v2/pipeline` replica destination.
pub struct TursoDestination {
    settings: TursoSettings,
    credentials: TursoCredentials,
    pipeline_url: String,
    describe_url: String,
    http: reqwest::blocking::Client,
    schema_ready: AtomicBool,
}

impl fmt::Debug for TursoDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TursoDestination")
            .field("settings", &self.settings)
            .field("describe_url", &self.describe_url)
            .finish_non_exhaustive()
    }
}

impl TursoDestination {
    /// Build a Turso replica destination.
    ///
    /// Must be called from a blocking thread (never inside the async runtime).
    ///
    /// # Errors
    ///
    /// Returns [`DestinationError::Rejected`] when the URL or credentials are
    /// invalid or carry inline secrets.
    pub fn new(
        settings: TursoSettings,
        credentials: TursoCredentials,
    ) -> Result<Self, DestinationError> {
        if credentials.auth_token.trim().is_empty() {
            return Err(DestinationError::Rejected {
                detail: "replication.turso auth token is empty".to_owned(),
            });
        }
        let (pipeline_url, describe_url) = normalize_turso_url(&settings.url)?;
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| DestinationError::Rejected {
                detail: format!(
                    "could not build the Turso replication HTTP client: {}",
                    super::redact_credentials(&e.to_string())
                ),
            })?;
        Ok(Self {
            settings,
            credentials,
            pipeline_url,
            describe_url,
            http,
            schema_ready: AtomicBool::new(false),
        })
    }

    fn ensure_schema(&self) -> Result<(), DestinationError> {
        if self.schema_ready.load(Ordering::Acquire) {
            return Ok(());
        }
        let body = serde_json::json!({
            "requests": [
                {
                    "type": "execute",
                    "stmt": {
                        "sql": "CREATE TABLE IF NOT EXISTS autumn_replica_objects (object_key TEXT PRIMARY KEY, body_b64 TEXT NOT NULL)"
                    }
                },
                { "type": "close" }
            ]
        });
        let _ = self.send_pipeline("ensure schema", &body)?;
        self.schema_ready.store(true, Ordering::Release);
        Ok(())
    }

    fn send_pipeline(
        &self,
        op: &'static str,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, DestinationError> {
        let response = self
            .http
            .post(&self.pipeline_url)
            .bearer_auth(self.credentials.auth_token.trim())
            .json(payload)
            .send()
            .map_err(|e| DestinationError::Io {
                op,
                detail: super::redact_credentials(&e.to_string()),
            })?;

        let status = response.status();
        let mut buf = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut buf)
            .map_err(|e| DestinationError::Io {
                op,
                detail: super::redact_credentials(&e.to_string()),
            })?;

        if !status.is_success() {
            let code = extract_error_code(&buf);
            return Err(DestinationError::Remote {
                op,
                status: status.as_u16(),
                code,
            });
        }

        let parsed: serde_json::Value =
            serde_json::from_slice(&buf).map_err(|e| DestinationError::Io {
                op,
                detail: format!("invalid JSON from Turso pipeline: {e}"),
            })?;

        if let Some(results) = parsed.get("results").and_then(serde_json::Value::as_array) {
            for item in results {
                if item.get("type").and_then(serde_json::Value::as_str) == Some("error") {
                    let code = item
                        .get("error")
                        .and_then(|err| err.get("code").or_else(|| err.get("message")))
                        .and_then(serde_json::Value::as_str)
                        .map(truncate_code);
                    return Err(DestinationError::Remote {
                        op,
                        status: status.as_u16(),
                        code,
                    });
                }
            }
        }

        Ok(parsed)
    }
}

impl ReplicaDestination for TursoDestination {
    fn describe(&self) -> String {
        self.describe_url.clone()
    }

    fn put(&self, key: &str, body: &[u8]) -> Result<(), DestinationError> {
        validate_key(key)?;
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_OBJECT_BYTES {
            return Err(DestinationError::Rejected {
                detail: format!(
                    "replica object {key:?} ({} bytes) exceeds Turso single-object limit ({MAX_OBJECT_BYTES} bytes)",
                    body.len()
                ),
            });
        }
        self.ensure_schema()?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(body);
        let payload = serde_json::json!({
            "requests": [
                {
                    "type": "execute",
                    "stmt": {
                        "sql": "INSERT INTO autumn_replica_objects (object_key, body_b64) VALUES (?1, ?2) ON CONFLICT(object_key) DO UPDATE SET body_b64 = excluded.body_b64",
                        "args": [
                            { "type": "text", "value": key },
                            { "type": "text", "value": encoded }
                        ]
                    }
                },
                { "type": "close" }
            ]
        });
        let _ = self.send_pipeline("put object", &payload)?;
        Ok(())
    }

    fn put_file(&self, key: &str, path: &Path) -> Result<(), DestinationError> {
        validate_key(key)?;
        let metadata =
            std::fs::metadata(path).map_err(DestinationError::io("stat upload source"))?;
        if metadata.len() > MAX_OBJECT_BYTES {
            return Err(DestinationError::Rejected {
                detail: format!(
                    "replica object {key:?} ({} bytes) exceeds Turso single-object limit ({MAX_OBJECT_BYTES} bytes)",
                    metadata.len()
                ),
            });
        }
        let bytes = std::fs::read(path).map_err(DestinationError::io("read upload source"))?;
        self.put(key, &bytes)
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, DestinationError> {
        validate_key(key)?;
        self.ensure_schema()?;
        let payload = serde_json::json!({
            "requests": [
                {
                    "type": "execute",
                    "stmt": {
                        "sql": "SELECT body_b64 FROM autumn_replica_objects WHERE object_key = ?1",
                        "args": [
                            { "type": "text", "value": key }
                        ]
                    }
                },
                { "type": "close" }
            ]
        });
        let response = self.send_pipeline("get object", &payload)?;
        let rows = response
            .get("results")
            .and_then(serde_json::Value::as_array)
            .and_then(|results| results.first())
            .and_then(|first| first.get("response"))
            .and_then(|resp| resp.get("result"))
            .and_then(|res| res.get("rows"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| DestinationError::Io {
                op: "get object",
                detail: "missing rows array in Turso pipeline response".to_owned(),
            })?;

        let Some(first_row) = rows.first().and_then(serde_json::Value::as_array) else {
            return Err(DestinationError::NotFound {
                key: key.to_owned(),
            });
        };
        let encoded = first_row
            .first()
            .and_then(|col| col.get("value"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| DestinationError::Io {
                op: "get object",
                detail: "missing base64 text column in Turso pipeline row".to_owned(),
            })?;

        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| DestinationError::Io {
                op: "get object",
                detail: format!("corrupt base64 payload in Turso replica row: {e}"),
            })
    }

    fn get_to_file(&self, key: &str, path: &Path) -> Result<(), DestinationError> {
        let bytes = self.get(key)?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(DestinationError::io("create download directory"))?;
        }
        std::fs::write(path, &bytes).map_err(DestinationError::io("write download file"))
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, DestinationError> {
        self.ensure_schema()?;
        let payload = serde_json::json!({
            "requests": [
                {
                    "type": "execute",
                    "stmt": {
                        "sql": "SELECT object_key FROM autumn_replica_objects ORDER BY object_key ASC"
                    }
                },
                { "type": "close" }
            ]
        });
        let response = self.send_pipeline("list objects", &payload)?;
        let rows = response
            .get("results")
            .and_then(serde_json::Value::as_array)
            .and_then(|results| results.first())
            .and_then(|first| first.get("response"))
            .and_then(|resp| resp.get("result"))
            .and_then(|res| res.get("rows"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| DestinationError::Io {
                op: "list objects",
                detail: "missing rows array in Turso pipeline response".to_owned(),
            })?;

        let mut keys = Vec::new();
        for row in rows {
            if let Some(key) = row
                .as_array()
                .and_then(|cols| cols.first())
                .and_then(|col| col.get("value"))
                .and_then(serde_json::Value::as_str)
                && key.starts_with(prefix)
            {
                keys.push(key.to_owned());
            }
        }
        keys.sort();
        Ok(keys)
    }

    fn delete(&self, key: &str) -> Result<(), DestinationError> {
        validate_key(key)?;
        self.ensure_schema()?;
        let payload = serde_json::json!({
            "requests": [
                {
                    "type": "execute",
                    "stmt": {
                        "sql": "DELETE FROM autumn_replica_objects WHERE object_key = ?1",
                        "args": [
                            { "type": "text", "value": key }
                        ]
                    }
                },
                { "type": "close" }
            ]
        });
        let _ = self.send_pipeline("delete object", &payload)?;
        Ok(())
    }
}

/// Validate a Turso endpoint URL and return `(pipeline_http_url, redacted_describe_url)`.
fn normalize_turso_url(raw: &str) -> Result<(String, String), DestinationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DestinationError::Rejected {
            detail: "replication.turso.url is empty".to_owned(),
        });
    }
    let http_candidate = if let Some(rest) = trimmed.strip_prefix("libsql://") {
        format!("https://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("turso://") {
        format!("https://{rest}")
    } else if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        trimmed.to_owned()
    } else {
        return Err(DestinationError::Rejected {
            detail: "replication.turso.url must use libsql://, turso://, https://, or http://"
                .to_owned(),
        });
    };

    let parsed = url::Url::parse(&http_candidate).map_err(|e| DestinationError::Rejected {
        detail: format!("invalid replication.turso.url: {e}"),
    })?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(DestinationError::Rejected {
            detail: "replication.turso.url must not carry inline userinfo credentials; use auth_token_env"
                .to_owned(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(DestinationError::Rejected {
            detail: "replication.turso.url must not carry a query string or fragment; pass the token via auth_token_env"
                .to_owned(),
        });
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(DestinationError::Rejected {
            detail: format!(
                "replication.turso.url must not carry a path prefix (found {:?})",
                parsed.path()
            ),
        });
    }
    let host = parsed.host_str().ok_or_else(|| DestinationError::Rejected {
        detail: "replication.turso.url has no host".to_owned(),
    })?;
    let authority = parsed
        .port()
        .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
    let pipeline_url = format!("{}://{authority}/v2/pipeline", parsed.scheme());
    let describe_url = format!("turso://{authority}");
    Ok((pipeline_url, describe_url))
}

fn extract_error_code(body: &[u8]) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
    let raw = parsed
        .get("error")
        .or_else(|| parsed.get("code"))
        .or_else(|| parsed.get("message"))
        .and_then(serde_json::Value::as_str)?;
    Some(truncate_code(raw))
}

fn truncate_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_CODE_LEN)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn credentials_and_destination_redact_auth_token_in_debug() {
        let creds = TursoCredentials {
            auth_token: "turso-super-secret-jwt".to_owned(),
        };
        let debug_creds = format!("{creds:?}");
        assert!(!debug_creds.contains("turso-super-secret-jwt"));
        assert!(debug_creds.contains("<redacted>"));

        let dest = TursoDestination::new(
            TursoSettings {
                url: "libsql://my-db-org.turso.io".to_owned(),
            },
            creds,
        )
        .expect("valid destination");
        let debug_dest = format!("{dest:?}");
        assert!(!debug_dest.contains("turso-super-secret-jwt"));
        assert_eq!(dest.describe(), "turso://my-db-org.turso.io");
    }

    #[test]
    fn url_validation_rejects_inline_secrets_and_bad_schemes() {
        let creds = TursoCredentials {
            auth_token: "token".to_owned(),
        };
        for bad in [
            "",
            "postgres://localhost/db",
            "libsql://user:secret@my-db.turso.io",
            "libsql://my-db.turso.io?authToken=secret",
            "libsql://my-db.turso.io#frag",
            "libsql://my-db.turso.io/custom/path",
        ] {
            assert!(
                TursoDestination::new(
                    TursoSettings {
                        url: bad.to_owned()
                    },
                    creds.clone()
                )
                .is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn turso_destination_round_trips_objects_against_loopback_pipeline() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");
        let store: Arc<Mutex<BTreeMap<String, String>>> = Arc::new(Mutex::new(BTreeMap::new()));
        let store_srv = Arc::clone(&store);

        let server = std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut content_length = 0usize;
                let mut saw_bearer = false;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(rest) = lower.strip_prefix("content-length:") {
                        content_length = rest.trim().parse().unwrap_or(0);
                    }
                    if lower.starts_with("authorization: bearer test-turso-token") {
                        saw_bearer = true;
                    }
                }
                if content_length == 0 {
                    break;
                }
                let mut body = vec![0u8; content_length];
                reader.read_exact(&mut body).expect("read body");
                assert!(saw_bearer, "missing expected Bearer token header");

                let req: serde_json::Value = serde_json::from_slice(&body).expect("json body");
                let stmt = &req["requests"][0]["stmt"];
                let sql = stmt["sql"].as_str().unwrap_or("");
                let response_json = if sql.starts_with("CREATE TABLE") {
                    serde_json::json!({
                        "results": [
                            { "type": "ok", "response": { "type": "execute", "result": { "affected_row_count": 0, "rows": [] } } },
                            { "type": "ok", "response": { "type": "close" } }
                        ]
                    })
                } else if sql.starts_with("INSERT INTO autumn_replica_objects") {
                    let key = stmt["args"][0]["value"].as_str().unwrap().to_owned();
                    let val = stmt["args"][1]["value"].as_str().unwrap().to_owned();
                    store_srv.lock().unwrap().insert(key, val);
                    serde_json::json!({
                        "results": [
                            { "type": "ok", "response": { "type": "execute", "result": { "affected_row_count": 1, "rows": [] } } },
                            { "type": "ok", "response": { "type": "close" } }
                        ]
                    })
                } else if sql.starts_with("SELECT body_b64 FROM autumn_replica_objects") {
                    let key = stmt["args"][0]["value"].as_str().unwrap();
                    let rows = match store_srv.lock().unwrap().get(key) {
                        Some(v) => vec![vec![serde_json::json!({ "type": "text", "value": v })]],
                        None => vec![],
                    };
                    serde_json::json!({
                        "results": [
                            { "type": "ok", "response": { "type": "execute", "result": { "affected_row_count": 0, "rows": rows } } },
                            { "type": "ok", "response": { "type": "close" } }
                        ]
                    })
                } else if sql.starts_with("SELECT object_key FROM autumn_replica_objects") {
                    let rows: Vec<Vec<serde_json::Value>> = store_srv
                        .lock()
                        .unwrap()
                        .keys()
                        .map(|k| vec![serde_json::json!({ "type": "text", "value": k })])
                        .collect();
                    serde_json::json!({
                        "results": [
                            { "type": "ok", "response": { "type": "execute", "result": { "affected_row_count": 0, "rows": rows } } },
                            { "type": "ok", "response": { "type": "close" } }
                        ]
                    })
                } else if sql.starts_with("DELETE FROM autumn_replica_objects") {
                    let key = stmt["args"][0]["value"].as_str().unwrap();
                    store_srv.lock().unwrap().remove(key);
                    serde_json::json!({
                        "results": [
                            { "type": "ok", "response": { "type": "execute", "result": { "affected_row_count": 1, "rows": [] } } },
                            { "type": "ok", "response": { "type": "close" } }
                        ]
                    })
                } else {
                    panic!("unexpected SQL: {sql}");
                };

                let encoded = serde_json::to_vec(&response_json).unwrap();
                let mut stream = reader.into_inner();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    encoded.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(&encoded).unwrap();
            }
        });

        let dest = TursoDestination::new(
            TursoSettings {
                url: format!("http://{addr}"),
            },
            TursoCredentials {
                auth_token: "test-turso-token".to_owned(),
            },
        )
        .expect("build destination");

        assert_eq!(dest.describe(), format!("turso://{addr}"));

        // 1. put + get
        dest.put("prod/generations/g1/snapshot.json", b"{\"gen\":1}")
            .expect("put snapshot.json");
        let fetched = dest
            .get("prod/generations/g1/snapshot.json")
            .expect("get snapshot.json");
        assert_eq!(fetched, b"{\"gen\":1}");

        // 2. put_file + get_to_file
        let dir = tempfile::tempdir().expect("tempdir");
        let upload_path = dir.path().join("seg.bin");
        let download_path = dir.path().join("out/seg.bin");
        std::fs::write(&upload_path, b"wal-segment-bytes").expect("write upload");
        dest.put_file("prod/generations/g1/segments/001.seg", &upload_path)
            .expect("put_file");
        dest.get_to_file("prod/generations/g1/segments/001.seg", &download_path)
            .expect("get_to_file");
        assert_eq!(
            std::fs::read(&download_path).expect("read download"),
            b"wal-segment-bytes"
        );

        // 3. list
        let listed = dest.list("prod/generations/g1/").expect("list");
        assert_eq!(
            listed,
            vec![
                "prod/generations/g1/segments/001.seg".to_owned(),
                "prod/generations/g1/snapshot.json".to_owned(),
            ]
        );

        // 4. delete + NotFound
        dest.delete("prod/generations/g1/snapshot.json")
            .expect("delete");
        let err = dest
            .get("prod/generations/g1/snapshot.json")
            .expect_err("deleted object must return NotFound");
        assert!(err.is_not_found(), "expected NotFound, got {err:?}");

        // Close server loop with an empty connect
        let _ = std::net::TcpStream::connect(addr);
        let _ = server.join();
    }
}
