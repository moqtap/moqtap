#[cfg(feature = "draft07")]
#[allow(dead_code)]
pub mod draft07_json;
#[cfg(feature = "draft08")]
#[allow(dead_code)]
pub mod draft08_json;
#[cfg(feature = "draft09")]
#[allow(dead_code)]
pub mod draft09_json;
#[cfg(feature = "draft10")]
#[allow(dead_code)]
pub mod draft10_json;
#[cfg(feature = "draft11")]
#[allow(dead_code)]
pub mod draft11_json;
#[cfg(feature = "draft12")]
#[allow(dead_code)]
pub mod draft12_json;
#[cfg(feature = "draft13")]
#[allow(dead_code)]
pub mod draft13_json;
#[cfg(feature = "draft14")]
#[allow(dead_code)]
pub mod draft14_json;
#[cfg(feature = "draft15")]
#[allow(dead_code)]
pub mod draft15_json;
#[cfg(feature = "draft16")]
#[allow(dead_code)]
pub mod draft16_json;
#[cfg(feature = "draft17")]
#[allow(dead_code)]
pub mod draft17_json;
#[cfg(feature = "draft18")]
#[allow(dead_code)]
pub mod draft18_json;
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
