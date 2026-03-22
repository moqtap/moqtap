#[cfg(feature = "draft07")]
#[allow(dead_code)]
pub mod draft07_json;
#[cfg(feature = "draft14")]
#[allow(dead_code)]
pub mod draft14_json;
#[allow(dead_code)]
pub mod params;

use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VectorFile {
    pub message_type: String,
    #[serde(default)]
    pub message_type_id: Option<String>,
    pub vectors: Vec<TestVector>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct TestVector {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    pub hex: String,
    pub decoded: Option<serde_json::Value>,
    pub error: Option<String>,
    pub canonical: Option<bool>,
}

impl TestVector {
    pub fn is_canonical(&self) -> bool {
        self.canonical.unwrap_or(true)
    }
}

pub fn load_vectors(path: &Path) -> VectorFile {
    let data = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("cannot read {}: {e} — did you init the submodule?", path.display())
    });
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

pub fn vectors_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}
