//! Source-reviewed, fail-closed comparison of the exposed configured profile.
//! Response values stay in wiped private storage; reports contain only reviewed
//! labels, inventory metadata, and equality/predicate booleans.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::restore_qualification::SecretJson;

const MAX_DEPTH: usize = 64;
const MAX_CATALOG_NODES: usize = 16_384;
const MAX_MODELS: usize = 1_024;
const MAX_LABELS: usize = 131_072;
const MAX_ITEMS: usize = 65_536;
const MAX_VALUE_NODES: usize = 1_048_576;
const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ComparisonMode {
    Public,
    Private,
    Volatile,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRule {
    pub required: bool,
    pub comparison: ComparisonMode,
    pub shape: ProfileShape,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileShape {
    Null {},
    Boolean {},
    Integer {},
    Number {},
    String {},
    Enum {
        values: Vec<String>,
    },
    Nullable {
        inner: Box<ProfileShape>,
    },
    Object {
        fields: BTreeMap<String, ProfileRule>,
    },
    ObjectMap {
        values: Box<ProfileRule>,
    },
    Array {
        items: Box<ProfileRule>,
    },
    OpaqueJson {},
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCatalog {
    pub source_review_reference: String,
    pub coverage_review_reference: String,
    pub model_ids: Vec<String>,
    pub virtual_model_id: Option<String>,
    pub global_settings: ProfileRule,
    pub model: ProfileRule,
    pub virtual_model: Option<ProfileRule>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileSummary {
    pub model_ids: Vec<String>,
    pub model_count: usize,
    pub virtual_model_present: bool,
    pub settings_present: BTreeMap<String, bool>,
}

/// Deliberately neither Debug, Serialize nor Clone.
pub struct ProfileSnapshot {
    raw: SecretJson,
    catalog_fingerprint: [u8; 32],
    summary: ProfileSummary,
}

#[derive(Debug, Serialize)]
pub struct PreStopReport {
    pub ps1: bool,
    pub ps2: bool,
    pub ps3: bool,
    pub ps4: bool,
    pub ps5: bool,
    pub ps6: bool,
}

impl PreStopReport {
    pub fn passed(&self) -> bool {
        self.ps1 && self.ps2 && self.ps3 && self.ps4 && self.ps5 && self.ps6
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileComparison {
    pub equal: bool,
    pub fields: BTreeMap<String, bool>,
    pub model_inventory_equal: bool,
    pub settings_presence_equal: bool,
}

fn symbol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn review_reference(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2_048 && !value.chars().any(char::is_control)
}

fn validate_shape(
    shape: &ProfileShape,
    comparison: ComparisonMode,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    *nodes += 1;
    ensure!(
        depth <= MAX_DEPTH && *nodes <= MAX_CATALOG_NODES,
        "profile catalog exceeds shape bounds"
    );
    match shape {
        ProfileShape::String {} | ProfileShape::OpaqueJson {} => {
            ensure!(
                comparison != ComparisonMode::Public,
                "profile catalog has an unrestricted public value"
            );
        }
        ProfileShape::Enum { values } => {
            ensure!(
                !values.is_empty() && values.len() <= MAX_ITEMS,
                "profile catalog has invalid enum bounds"
            );
            *nodes += values.len();
            ensure!(
                *nodes <= MAX_CATALOG_NODES,
                "profile catalog exceeds enum bounds"
            );
            let mut unique = BTreeSet::new();
            for value in values {
                ensure!(
                    value.len() <= 256
                        && !value.chars().any(char::is_control)
                        && unique.insert(value),
                    "profile catalog has invalid enum values"
                );
            }
        }
        ProfileShape::Nullable { inner } => {
            ensure!(
                !matches!(inner.as_ref(), ProfileShape::Nullable { .. }),
                "profile catalog has redundant nullability"
            );
            validate_shape(inner, comparison, depth + 1, nodes)?;
        }
        ProfileShape::ObjectMap { values } => {
            ensure!(
                comparison != ComparisonMode::Public && values.required,
                "profile catalog object maps must be private or volatile with required values"
            );
            validate_shape(&values.shape, values.comparison, depth + 1, nodes)?;
        }
        ProfileShape::Object { fields } => {
            ensure!(
                fields.len() <= MAX_CATALOG_NODES,
                "profile catalog exceeds object bounds"
            );
            for (key, rule) in fields {
                ensure!(symbol(key), "profile catalog has an invalid field symbol");
                validate_shape(&rule.shape, rule.comparison, depth + 1, nodes)?;
            }
        }
        ProfileShape::Array { items } => {
            ensure!(
                items.required,
                "profile catalog array items must be required"
            );
            validate_shape(&items.shape, items.comparison, depth + 1, nodes)?;
        }
        ProfileShape::Null {}
        | ProfileShape::Boolean {}
        | ProfileShape::Integer {}
        | ProfileShape::Number {} => {}
    }
    Ok(())
}

fn object_fields(rule: &ProfileRule) -> Result<&BTreeMap<String, ProfileRule>> {
    match &rule.shape {
        ProfileShape::Object { fields } => Ok(fields),
        _ => anyhow::bail!("profile catalog root must be a strict object"),
    }
}

fn validate_id_rule(fields: &BTreeMap<String, ProfileRule>, ids: &BTreeSet<&str>) -> Result<()> {
    let valid = fields.get("id").is_some_and(|rule| {
        rule.required
            && rule.comparison != ComparisonMode::Volatile
            && matches!(&rule.shape, ProfileShape::Enum { values }
                if values.iter().map(String::as_str).collect::<BTreeSet<_>>() == *ids)
    });
    ensure!(
        valid,
        "profile catalog identity enumeration does not match inventory"
    );
    Ok(())
}

impl ProfileCatalog {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            review_reference(&self.source_review_reference)
                && review_reference(&self.coverage_review_reference),
            "profile catalog requires bounded review references"
        );
        ensure!(
            !self.model_ids.is_empty() && self.model_ids.len() <= MAX_MODELS,
            "profile catalog has invalid inventory bounds"
        );
        let mut ids = BTreeSet::new();
        for id in &self.model_ids {
            ensure!(
                symbol(id) && ids.insert(id.as_str()),
                "profile catalog has invalid model identifiers"
            );
        }
        ensure!(
            self.virtual_model_id.is_some() == self.virtual_model.is_some(),
            "profile catalog virtual identity and shape must be paired"
        );
        ensure!(
            self.global_settings.required
                && self.model.required
                && self.global_settings.comparison != ComparisonMode::Volatile
                && self.model.comparison != ComparisonMode::Volatile,
            "profile catalog roots must be required and compared"
        );
        object_fields(&self.global_settings)?;
        let fields = object_fields(&self.model)?;
        validate_id_rule(fields, &ids)?;
        let settings = fields
            .get("settings")
            .ok_or_else(|| anyhow::anyhow!("profile catalog requires optional model settings"))?;
        ensure!(
            !settings.required && settings.comparison != ComparisonMode::Volatile,
            "profile catalog settings must be optional and compared"
        );
        ensure!(
            object_fields(settings)?.values().all(|rule| rule.required),
            "profile catalog settings fields must all be required"
        );
        if let (Some(id), Some(rule)) = (&self.virtual_model_id, &self.virtual_model) {
            ensure!(
                symbol(id)
                    && !ids.contains(id.as_str())
                    && rule.comparison != ComparisonMode::Volatile,
                "profile catalog has invalid virtual identity"
            );
            let fields = object_fields(rule)?;
            validate_id_rule(fields, &BTreeSet::from([id.as_str()]))?;
            ensure!(
                fields.get("virtual").is_some_and(|field| field.required
                    && matches!(field.shape, ProfileShape::Boolean {})
                    && field.comparison != ComparisonMode::Volatile),
                "profile catalog requires a compared virtual discriminator"
            );
        }
        let mut global_nodes = 0;
        validate_shape(
            &self.global_settings.shape,
            self.global_settings.comparison,
            0,
            &mut global_nodes,
        )?;
        let mut model_nodes = 0;
        validate_shape(
            &self.model.shape,
            self.model.comparison,
            0,
            &mut model_nodes,
        )?;
        let mut virtual_nodes = 0;
        if let Some(rule) = &self.virtual_model {
            validate_shape(&rule.shape, rule.comparison, 0, &mut virtual_nodes)?;
        }
        ensure!(
            global_nodes + model_nodes * self.model_ids.len() + virtual_nodes <= MAX_LABELS,
            "profile catalog exceeds report bounds"
        );
        Ok(())
    }

    pub fn compared_labels(&self) -> Vec<String> {
        self.labels(false)
    }

    pub fn volatile_labels(&self) -> Vec<String> {
        self.labels(true)
    }

    fn labels(&self, volatile: bool) -> Vec<String> {
        // Invalid catalogs never become an output-label authority.
        if self.validate().is_err() {
            return Vec::new();
        }
        let mut labels = Vec::new();
        collect_labels(
            &self.global_settings,
            "/global_settings",
            volatile,
            &mut labels,
        );
        for id in &self.model_ids {
            collect_labels(
                &self.model,
                &format!("/models_by_id/{id}"),
                volatile,
                &mut labels,
            );
        }
        if let (Some(id), Some(rule)) = (&self.virtual_model_id, &self.virtual_model) {
            collect_labels(rule, &format!("/models_by_id/{id}"), volatile, &mut labels);
        }
        labels.sort();
        labels
    }

    fn fingerprint(&self) -> Result<[u8; 32]> {
        struct CatalogHash(Sha256);
        impl Write for CatalogHash {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = CatalogHash(Sha256::new());
        // Only reviewed schema metadata is hashed, never response values.
        serde_json::to_writer(&mut writer, self)
            .map_err(|_| anyhow::anyhow!("profile catalog encoding failed"))?;
        Ok(writer.0.finalize().into())
    }
}

fn collect_labels(rule: &ProfileRule, path: &str, volatile: bool, labels: &mut Vec<String>) {
    if rule.comparison == ComparisonMode::Volatile {
        if volatile {
            labels.push(path.to_owned());
        }
        return;
    }
    if !volatile {
        labels.push(path.to_owned());
    }
    collect_shape_labels(&rule.shape, path, volatile, labels);
}

fn collect_shape_labels(
    shape: &ProfileShape,
    path: &str,
    volatile: bool,
    labels: &mut Vec<String>,
) {
    match shape {
        ProfileShape::Nullable { inner } => collect_shape_labels(inner, path, volatile, labels),
        ProfileShape::Object { fields } => {
            for (key, rule) in fields {
                collect_labels(rule, &format!("{path}/{key}"), volatile, labels);
            }
        }
        ProfileShape::Array { items } => {
            collect_labels(items, &format!("{path}/*"), volatile, labels)
        }
        ProfileShape::ObjectMap { values } => {
            collect_labels(values, &format!("{path}/*"), volatile, labels)
        }
        _ => {}
    }
}

// Bound opaque payloads as well as typed values, without ever exposing their keys.
fn validate_value_bounds(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    bytes: &mut usize,
) -> Result<()> {
    *nodes += 1;
    ensure!(
        depth <= MAX_DEPTH && *nodes <= MAX_VALUE_NODES,
        "profile response exceeds shape bounds"
    );
    match value {
        Value::String(text) => *bytes = bytes.saturating_add(text.len()),
        Value::Array(items) => {
            ensure!(
                items.len() <= MAX_ITEMS,
                "profile response exceeds array bounds"
            );
            for item in items {
                validate_value_bounds(item, depth + 1, nodes, bytes)?;
            }
        }
        Value::Object(fields) => {
            ensure!(
                fields.len() <= MAX_ITEMS,
                "profile response exceeds object bounds"
            );
            for (key, value) in fields {
                *bytes = bytes.saturating_add(key.len());
                validate_value_bounds(value, depth + 1, nodes, bytes)?;
            }
        }
        _ => {}
    }
    ensure!(
        *bytes <= MAX_VALUE_BYTES,
        "profile response exceeds byte bounds"
    );
    Ok(())
}

fn validate_value(value: Option<&Value>, rule: &ProfileRule) -> Result<()> {
    match value {
        Some(value) => validate_value_shape(value, &rule.shape),
        None => {
            ensure!(
                !rule.required,
                "profile response is missing a required field"
            );
            Ok(())
        }
    }
}

fn validate_value_shape(value: &Value, shape: &ProfileShape) -> Result<()> {
    let valid = match shape {
        ProfileShape::Null {} => value.is_null(),
        ProfileShape::Boolean {} => value.is_boolean(),
        ProfileShape::Integer {} => value.is_i64() || value.is_u64(),
        ProfileShape::Number {} => value.is_number(),
        ProfileShape::String {} => value.is_string(),
        ProfileShape::Enum { values } => value
            .as_str()
            .is_some_and(|value| values.iter().any(|item| item == value)),
        ProfileShape::Nullable { inner } => {
            if !value.is_null() {
                validate_value_shape(value, inner)?;
            }
            true
        }
        ProfileShape::Object { fields } => {
            let object = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("profile response has an invalid field type"))?;
            ensure!(
                object.keys().all(|key| fields.contains_key(key)),
                "profile response has an unclassified field"
            );
            for (key, rule) in fields {
                validate_value(object.get(key), rule)?;
            }
            true
        }
        ProfileShape::ObjectMap { values } => {
            let object = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("profile response has an invalid field type"))?;
            for value in object.values() {
                validate_value(Some(value), values)?;
            }
            true
        }
        ProfileShape::Array { items } => {
            let array = value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("profile response has an invalid field type"))?;
            for value in array {
                validate_value(Some(value), items)?;
            }
            true
        }
        ProfileShape::OpaqueJson {} => true,
    };
    ensure!(
        valid,
        "profile response has an invalid field type or enumeration"
    );
    Ok(())
}

impl ProfileSnapshot {
    pub fn capture(raw: Value, catalog: &ProfileCatalog) -> Result<Self> {
        let mut raw = SecretJson(raw);
        catalog.validate()?;
        validate_value_bounds(&raw.0, 0, &mut 0, &mut 0)?;
        let root = raw
            .0
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("profile response root must be an object"))?;
        ensure!(
            root.len() == 2 && root.contains_key("global_settings") && root.contains_key("models"),
            "profile response root has an invalid field set"
        );
        validate_value(root.get("global_settings"), &catalog.global_settings)?;
        let envelope = root
            .get("models")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow::anyhow!("profile model envelope must be an object"))?;
        ensure!(
            envelope.len() == 1 && envelope.contains_key("models"),
            "profile model envelope has an invalid field set"
        );
        let entries = envelope
            .get("models")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("profile model inventory must be an array"))?;
        ensure!(
            entries.len() >= catalog.model_ids.len()
                && entries.len()
                    <= catalog.model_ids.len() + usize::from(catalog.virtual_model_id.is_some()),
            "profile model inventory has an invalid count"
        );
        let mut seen = BTreeSet::new();
        let mut settings_present = BTreeMap::new();
        let mut virtual_model_present = false;
        for entry in entries {
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("profile model identity is missing or invalid"))?;
            ensure!(seen.insert(id), "profile model identity is duplicated");
            if let Some(reviewed_id) = catalog
                .model_ids
                .iter()
                .find(|reviewed| reviewed.as_str() == id)
            {
                validate_value(Some(entry), &catalog.model)?;
                ensure!(
                    entry
                        .get("virtual")
                        .is_none_or(|value| value.as_bool() == Some(false)),
                    "profile real model has an invalid discriminator"
                );
                settings_present.insert(reviewed_id.clone(), entry.get("settings").is_some());
            } else if catalog.virtual_model_id.as_deref() == Some(id) {
                let rule = catalog
                    .virtual_model
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("profile virtual model is unclassified"))?;
                validate_value(Some(entry), rule)?;
                ensure!(
                    entry.get("virtual").and_then(Value::as_bool) == Some(true),
                    "profile virtual model has an invalid discriminator"
                );
                virtual_model_present = true;
            } else {
                anyhow::bail!("profile model identity is not enrolled");
            }
        }
        ensure!(
            catalog
                .model_ids
                .iter()
                .all(|id| seen.contains(id.as_str())),
            "profile model inventory is incomplete"
        );
        let mut model_ids = catalog.model_ids.clone();
        model_ids.sort();
        let summary = ProfileSummary {
            model_count: model_ids.len(),
            model_ids,
            virtual_model_present,
            settings_present,
        };
        let catalog_fingerprint = catalog.fingerprint()?;
        // Validation precedes normalization. Every moved subtree immediately has
        // a wiping owner, including partially assembled canonical storage.
        let mut canonical = SecretJson(Value::Object(serde_json::Map::new()));
        let entries = raw
            .0
            .get_mut("models")
            .and_then(|value| value.get_mut("models"))
            .and_then(Value::as_array_mut)
            .expect("validated model envelope");
        while let Some(value) = entries.pop() {
            let mut entry = SecretJson(value);
            let id = entry
                .0
                .get("id")
                .and_then(Value::as_str)
                .expect("validated identity");
            let reviewed = catalog
                .model_ids
                .iter()
                .chain(catalog.virtual_model_id.iter())
                .find(|reviewed| reviewed.as_str() == id)
                .expect("validated inventory");
            canonical
                .0
                .as_object_mut()
                .expect("canonical object")
                .insert(reviewed.clone(), std::mem::take(&mut entry.0));
        }
        // The old envelope now contains only an empty array, but still receives
        // a wiping owner rather than relying on that incidental representation.
        let old = std::mem::replace(
            raw.0.get_mut("models").expect("validated envelope"),
            std::mem::take(&mut canonical.0),
        );
        drop(SecretJson(old));
        Ok(Self {
            raw,
            catalog_fingerprint,
            summary,
        })
    }

    pub fn summary(&self) -> &ProfileSummary {
        &self.summary
    }

    pub fn prestop(&self, expected_health: &Value) -> PreStopReport {
        let models = self
            .raw
            .0
            .get("models")
            .and_then(Value::as_object)
            .expect("canonical models");
        let ps1 = self.summary.model_ids.iter().all(|id| {
            let entry = &models[id];
            entry.get("pinned").and_then(Value::as_bool) == Some(false)
                && entry.get("settings").is_none_or(|settings| {
                    settings.get("is_pinned").and_then(Value::as_bool) == Some(false)
                })
        });
        let ps2 = expected_health
            .pointer("/engine_pool/model_count")
            .and_then(Value::as_u64)
            == Some(self.summary.model_count as u64);
        let mut discovered_default = None;
        let mut default_count = 0;
        let mut default_types_valid = true;
        for id in &self.summary.model_ids {
            let entry = &models[id];
            if entry.get("is_default").and_then(Value::as_bool).is_none() {
                default_types_valid = false;
            }
            if let Some(settings) = entry.get("settings") {
                match settings.get("is_default").and_then(Value::as_bool) {
                    Some(true) => {
                        default_count += 1;
                        discovered_default = Some(id.as_str());
                    }
                    Some(false) => {}
                    None => default_types_valid = false,
                }
            }
        }
        let ps3 = default_types_valid
            && default_count == 1
            && discovered_default == expected_health.get("default_model").and_then(Value::as_str)
            && self.summary.model_ids.iter().all(|id| {
                models[id].get("is_default").and_then(Value::as_bool)
                    == Some(Some(id.as_str()) == discovered_default)
            });
        let ps4 = self
            .raw
            .0
            .pointer("/global_settings/scheduler/max_concurrent_requests")
            .and_then(Value::as_u64)
            == Some(8);
        let ps5 = self
            .raw
            .0
            .pointer("/global_settings/auth/api_key_set")
            .and_then(Value::as_bool)
            == Some(true)
            && self
                .raw
                .0
                .pointer("/global_settings/auth/skip_api_key_verification")
                .and_then(Value::as_bool)
                == Some(false);
        // Runtime activity is volatile for equality, but must still prove that
        // this pre-stop transaction remains confined to the named local scope.
        let ps6 = self
            .raw
            .0
            .pointer("/global_settings/server/distributed_inference_active")
            .and_then(Value::as_bool)
            == Some(false)
            && self
                .raw
                .0
                .pointer("/global_settings/server/distributed_inference_enabled")
                .and_then(Value::as_bool)
                == Some(false)
            && self.summary.model_ids.iter().all(|id| {
                models[id].get("distributed").and_then(Value::as_bool) == Some(false)
                    && models[id].get("cluster").is_some_and(Value::is_null)
            });
        PreStopReport {
            ps1,
            ps2,
            ps3,
            ps4,
            ps5,
            ps6,
        }
    }

    pub fn compare(&self, other: &Self, catalog: &ProfileCatalog) -> Result<ProfileComparison> {
        catalog.validate()?;
        let fingerprint = catalog.fingerprint()?;
        ensure!(
            self.catalog_fingerprint == fingerprint && other.catalog_fingerprint == fingerprint,
            "profile comparison catalog does not match captured capability"
        );
        let model_inventory_equal = self.summary.model_ids == other.summary.model_ids
            && self.summary.virtual_model_present == other.summary.virtual_model_present;
        let settings_presence_equal =
            self.summary.settings_present == other.summary.settings_present;
        let mut fields = catalog
            .compared_labels()
            .into_iter()
            .map(|label| (label, true))
            .collect();
        compare_rule(
            self.raw.0.get("global_settings"),
            other.raw.0.get("global_settings"),
            &catalog.global_settings,
            "/global_settings",
            &mut fields,
        );
        let old_models = self.raw.0.get("models").expect("canonical models");
        let new_models = other.raw.0.get("models").expect("canonical models");
        for id in &catalog.model_ids {
            compare_rule(
                old_models.get(id),
                new_models.get(id),
                &catalog.model,
                &format!("/models_by_id/{id}"),
                &mut fields,
            );
        }
        if let (Some(id), Some(rule)) = (&catalog.virtual_model_id, &catalog.virtual_model) {
            compare_rule(
                old_models.get(id),
                new_models.get(id),
                rule,
                &format!("/models_by_id/{id}"),
                &mut fields,
            );
        }
        Ok(ProfileComparison {
            equal: model_inventory_equal
                && settings_presence_equal
                && fields.values().all(|equal| *equal),
            fields,
            model_inventory_equal,
            settings_presence_equal,
        })
    }
}

fn compare_rule(
    old: Option<&Value>,
    new: Option<&Value>,
    rule: &ProfileRule,
    path: &str,
    fields: &mut BTreeMap<String, bool>,
) -> bool {
    if rule.comparison == ComparisonMode::Volatile {
        return true;
    }
    let equal = compare_shape(old, new, &rule.shape, path, fields);
    // Wildcard labels aggregate all array positions without exposing indexes or
    // keys from opaque payloads. A later equal position cannot erase a mismatch.
    *fields
        .get_mut(path)
        .expect("catalog supplies every compared label") &= equal;
    equal
}

fn state(value: Option<&Value>) -> u8 {
    match value {
        None => 0,
        Some(Value::Null) => 1,
        Some(_) => 2,
    }
}

fn compare_shape(
    old: Option<&Value>,
    new: Option<&Value>,
    shape: &ProfileShape,
    path: &str,
    fields: &mut BTreeMap<String, bool>,
) -> bool {
    let mut equal = state(old) == state(new);
    match shape {
        ProfileShape::Nullable { inner } => {
            equal &= compare_shape(
                old.filter(|value| !value.is_null()),
                new.filter(|value| !value.is_null()),
                inner,
                path,
                fields,
            );
        }
        ProfileShape::Object { fields: schema } => {
            for (key, rule) in schema {
                equal &= compare_rule(
                    old.and_then(|value| value.get(key)),
                    new.and_then(|value| value.get(key)),
                    rule,
                    &format!("{path}/{key}"),
                    fields,
                );
            }
        }
        ProfileShape::ObjectMap { values } => {
            let left = old.and_then(Value::as_object);
            let right = new.and_then(Value::as_object);
            let item_path = format!("{path}/*");
            if let Some(left) = left {
                for (key, value) in left {
                    let other = right.and_then(|right| right.get(key));
                    equal &= other.is_some();
                    equal &= compare_rule(Some(value), other, values, &item_path, fields);
                }
            }
            if let Some(right) = right {
                for (key, value) in right {
                    if left.is_none_or(|left| !left.contains_key(key)) {
                        equal = false;
                        compare_rule(None, Some(value), values, &item_path, fields);
                    }
                }
            }
        }
        ProfileShape::Array { items } => {
            let left = old
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let right = new
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            equal &= left.len() == right.len();
            let item_path = format!("{path}/*");
            for index in 0..left.len().max(right.len()) {
                equal &= compare_rule(left.get(index), right.get(index), items, &item_path, fields);
            }
        }
        _ => equal &= old == new,
    }
    equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(shape: ProfileShape) -> ProfileRule {
        ProfileRule {
            required: true,
            comparison: ComparisonMode::Private,
            shape,
        }
    }

    fn object(fields: Vec<(&str, ProfileRule)>) -> ProfileRule {
        rule(ProfileShape::Object {
            fields: fields
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        })
    }

    fn nullable(shape: ProfileShape) -> ProfileRule {
        rule(ProfileShape::Nullable {
            inner: Box::new(shape),
        })
    }

    fn catalog() -> ProfileCatalog {
        let mut settings = object(vec![
            ("is_pinned", rule(ProfileShape::Boolean {})),
            ("is_default", rule(ProfileShape::Boolean {})),
            ("description", nullable(ProfileShape::String {})),
            ("payload", rule(ProfileShape::OpaqueJson {})),
        ]);
        settings.required = false;
        let mut optional = nullable(ProfileShape::String {});
        optional.required = false;
        let mut used = rule(ProfileShape::Integer {});
        used.comparison = ComparisonMode::Volatile;
        let mut active = rule(ProfileShape::Boolean {});
        active.comparison = ComparisonMode::Volatile;
        let mut cluster = rule(ProfileShape::OpaqueJson {});
        cluster.comparison = ComparisonMode::Volatile;
        ProfileCatalog {
            source_review_reference: "synthetic-source".into(),
            coverage_review_reference: "synthetic-coverage".into(),
            model_ids: vec!["beta".into(), "alpha".into()],
            virtual_model_id: None,
            virtual_model: None,
            global_settings: object(vec![
                (
                    "server",
                    object(vec![
                        ("distributed_inference_active", active),
                        (
                            "distributed_inference_enabled",
                            rule(ProfileShape::Boolean {}),
                        ),
                    ]),
                ),
                (
                    "scheduler",
                    object(vec![(
                        "max_concurrent_requests",
                        rule(ProfileShape::Integer {}),
                    )]),
                ),
                (
                    "auth",
                    object(vec![
                        ("api_key_set", rule(ProfileShape::Boolean {})),
                        ("skip_api_key_verification", rule(ProfileShape::Boolean {})),
                        ("api_key", rule(ProfileShape::String {})),
                        (
                            "sub_keys",
                            rule(ProfileShape::Array {
                                items: Box::new(object(vec![
                                    ("key", rule(ProfileShape::String {})),
                                    ("last_used", used),
                                ])),
                            }),
                        ),
                    ]),
                ),
                ("optional", optional),
                (
                    "map",
                    rule(ProfileShape::ObjectMap {
                        values: Box::new(rule(ProfileShape::String {})),
                    }),
                ),
            ]),
            model: object(vec![
                (
                    "id",
                    rule(ProfileShape::Enum {
                        values: vec!["alpha".into(), "beta".into()],
                    }),
                ),
                ("pinned", rule(ProfileShape::Boolean {})),
                ("is_default", rule(ProfileShape::Boolean {})),
                ("distributed", rule(ProfileShape::Boolean {})),
                ("cluster", cluster),
                ("settings", settings),
            ]),
        }
    }

    fn raw() -> Value {
        json!({
            "global_settings": {
                "server": {"distributed_inference_active": false, "distributed_inference_enabled": false},
                "scheduler": {"max_concurrent_requests": 8},
                "auth": {
                    "api_key_set": true, "skip_api_key_verification": false,
                    "api_key": "SYNTHETIC-PRIVATE-KEY",
                    "sub_keys": [
                        {"key": "SYNTHETIC-SUB-ONE", "last_used": 1},
                        {"key": "SYNTHETIC-SUB-TWO", "last_used": 2}
                    ]
                },
                "map": {"SYNTHETIC-DYNAMIC-KEY": "SYNTHETIC-MAP-VALUE"}
            },
            "models": {"models": [
                {"id": "alpha", "pinned": false, "is_default": true,
                 "distributed": false, "cluster": null,
                 "settings": {"is_pinned": false, "is_default": true,
                              "description": null, "payload": {"SYNTHETIC-OPAQUE-KEY": "SYNTHETIC-OPAQUE-VALUE"}}},
                {"id": "beta", "pinned": false, "is_default": false,
                 "distributed": false, "cluster": null,
                 "settings": {"is_pinned": false, "is_default": false,
                              "description": "SYNTHETIC-DESCRIPTION", "payload": []}}
            ]}
        })
    }

    fn health() -> Value {
        json!({"engine_pool": {"model_count": 2}, "default_model": "alpha"})
    }

    fn compare(left: Value, right: Value, catalog: &ProfileCatalog) -> ProfileComparison {
        ProfileSnapshot::capture(left, catalog)
            .unwrap()
            .compare(&ProfileSnapshot::capture(right, catalog).unwrap(), catalog)
            .unwrap()
    }

    #[test]
    fn optional_private_absent_null_and_value_are_distinct() {
        let catalog = catalog();
        let absent = raw();
        let mut null = raw();
        null["global_settings"]["optional"] = Value::Null;
        let mut value = raw();
        value["global_settings"]["optional"] = json!("SYNTHETIC-OPTIONAL-SECRET");
        for (left, right) in [
            (absent.clone(), null.clone()),
            (null, value.clone()),
            (absent, value),
        ] {
            let report = compare(left, right, &catalog);
            assert!(!report.equal);
            assert!(!report.fields["/global_settings/optional"]);
        }
        let mut required_null = raw();
        required_null["models"]["models"][0]["settings"]["description"] = Value::Null;
        assert!(ProfileSnapshot::capture(required_null, &catalog).is_ok());
        let mut missing = raw();
        missing["models"]["models"][0]["settings"]
            .as_object_mut()
            .unwrap()
            .remove("description");
        assert!(ProfileSnapshot::capture(missing, &catalog).is_err());
    }

    #[test]
    fn private_changes_in_every_model_are_reported_without_values_or_dynamic_keys() {
        let catalog = catalog();
        let mut changed = raw();
        changed["global_settings"]["auth"]["api_key"] = json!("SYNTHETIC-CHANGED-SECRET");
        changed["models"]["models"][0]["settings"]["payload"] =
            json!({"SYNTHETIC-CHANGED-DYNAMIC": 3});
        changed["models"]["models"][1]["settings"]["description"] =
            json!("SYNTHETIC-CHANGED-DESCRIPTION");
        let report = compare(raw(), changed, &catalog);
        assert!(!report.equal);
        for label in [
            "/global_settings/auth/api_key",
            "/models_by_id/alpha/settings/payload",
            "/models_by_id/beta/settings/description",
        ] {
            assert!(!report.fields[label]);
        }
        let snapshot = ProfileSnapshot::capture(raw(), &catalog).unwrap();
        let output = format!(
            "{} {:?} {} {:?}",
            serde_json::to_string(&report).unwrap(),
            report,
            serde_json::to_string(snapshot.summary()).unwrap(),
            snapshot.prestop(&health())
        );
        assert!(!output.contains("SYNTHETIC-"));
        assert!(!output.contains("SYNTHETIC-DYNAMIC-KEY"));
        assert_eq!(snapshot.summary().model_ids, ["alpha", "beta"]);
    }

    #[test]
    fn array_order_cardinality_and_nested_volatility_are_independent() {
        let catalog = catalog();
        let mut changed = raw();
        changed["global_settings"]["auth"]["sub_keys"][0]["last_used"] = json!(999);
        assert!(compare(raw(), changed, &catalog).equal);
        assert!(
            catalog
                .volatile_labels()
                .contains(&"/global_settings/auth/sub_keys/*/last_used".into())
        );
        let mut changed = raw();
        changed["global_settings"]["auth"]["sub_keys"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        let report = compare(raw(), changed, &catalog);
        assert!(!report.equal);
        assert!(!report.fields["/global_settings/auth/sub_keys/*/key"]);
        let mut changed = raw();
        changed["global_settings"]["auth"]["sub_keys"]
            .as_array_mut()
            .unwrap()
            .pop();
        let report = compare(raw(), changed, &catalog);
        assert!(!report.fields["/global_settings/auth/sub_keys"]);
        let mut changed = raw();
        changed["global_settings"]["auth"]["sub_keys"][0]["key"] = json!("SYNTHETIC-UNEQUAL-FIRST");
        assert!(!compare(raw(), changed, &catalog).fields["/global_settings/auth/sub_keys/*/key"]);
        let mut malformed = raw();
        malformed["global_settings"]["auth"]["sub_keys"][0]["last_used"] =
            json!("SYNTHETIC-WRONG-TYPE");
        assert!(ProfileSnapshot::capture(malformed, &catalog).is_err());
    }

    #[test]
    fn strict_shapes_reject_unknown_missing_and_wrong_types_at_every_depth() {
        let catalog = catalog();
        let changes = [
            ("/global_settings/auth/api_key_set", json!(1)),
            (
                "/global_settings/scheduler/max_concurrent_requests",
                json!(8.0),
            ),
            ("/global_settings/auth/api_key", Value::Null),
            ("/global_settings/auth/sub_keys", json!({})),
            ("/models/models/1/settings", Value::Null),
        ];
        for (pointer, value) in changes {
            let mut malformed = raw();
            *malformed.pointer_mut(pointer).unwrap() = value;
            assert!(ProfileSnapshot::capture(malformed, &catalog).is_err());
        }
        for pointer in [
            "",
            "/models",
            "/global_settings",
            "/global_settings/auth",
            "/models/models/1/settings",
            "/global_settings/auth/sub_keys/0",
        ] {
            let mut malformed = raw();
            malformed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(
                    "SYNTHETIC-UNKNOWN-SECRET-KEY".into(),
                    json!("SYNTHETIC-UNKNOWN-SECRET"),
                );
            let error = ProfileSnapshot::capture(malformed, &catalog)
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("SYNTHETIC"));
        }
        for (pointer, key) in [
            ("/global_settings", "auth"),
            ("/global_settings/auth", "api_key"),
            ("/models/models/1/settings", "payload"),
        ] {
            let mut malformed = raw();
            malformed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(ProfileSnapshot::capture(malformed, &catalog).is_err());
        }
    }

    #[test]
    fn inventory_is_canonical_by_id_and_settings_presence_is_compared() {
        let catalog = catalog();
        let mut reordered = raw();
        reordered["models"]["models"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(compare(raw(), reordered, &catalog).equal);
        for id in ["alpha", "SYNTHETIC-UNKNOWN-ID"] {
            let mut invalid = raw();
            invalid["models"]["models"][1]["id"] = json!(id);
            let error = ProfileSnapshot::capture(invalid, &catalog)
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("SYNTHETIC"));
        }
        let mut missing = raw();
        missing["models"]["models"].as_array_mut().unwrap().pop();
        assert!(ProfileSnapshot::capture(missing, &catalog).is_err());
        let mut no_settings = raw();
        no_settings["models"]["models"][1]
            .as_object_mut()
            .unwrap()
            .remove("settings");
        let report = compare(raw(), no_settings.clone(), &catalog);
        assert!(!report.equal);
        assert!(!report.settings_presence_equal);
        assert!(!report.fields["/models_by_id/beta/settings"]);
        let snapshot = ProfileSnapshot::capture(no_settings, &catalog).unwrap();
        assert!(!snapshot.summary().settings_present["beta"]);
        assert!(snapshot.prestop(&health()).passed());
    }

    #[test]
    fn prestop_predicates_each_fail_closed() {
        let catalog = catalog();
        let baseline = ProfileSnapshot::capture(raw(), &catalog).unwrap();
        assert!(baseline.prestop(&health()).passed());
        for (pointer, value, predicate) in [
            ("/models/models/1/pinned", json!(true), 1),
            ("/models/models/1/settings/is_pinned", json!(true), 1),
            ("/models/models/0/settings/is_default", json!(false), 3),
            ("/models/models/1/settings/is_default", json!(true), 3),
            ("/models/models/1/is_default", json!(true), 3),
            ("/models/models/0/is_default", json!(false), 3),
            (
                "/global_settings/scheduler/max_concurrent_requests",
                json!(9),
                4,
            ),
            ("/global_settings/auth/api_key_set", json!(false), 5),
            (
                "/global_settings/auth/skip_api_key_verification",
                json!(true),
                5,
            ),
        ] {
            let mut changed = raw();
            *changed.pointer_mut(pointer).unwrap() = value;
            let report = ProfileSnapshot::capture(changed, &catalog)
                .unwrap()
                .prestop(&health());
            assert!(!report.passed());
            assert!(!match predicate {
                1 => report.ps1,
                3 => report.ps3,
                4 => report.ps4,
                5 => report.ps5,
                _ => unreachable!(),
            });
        }
        for expected in [
            json!({}),
            json!({"engine_pool":{"model_count": 3}}),
            json!({"engine_pool":{"model_count": "2"}}),
        ] {
            assert!(!baseline.prestop(&expected).ps2);
        }
        for default in [json!("beta"), Value::Null, json!(true)] {
            let mut expected = health();
            expected["default_model"] = default;
            assert!(!baseline.prestop(&expected).ps3);
        }
        // A reviewed schema that lacks a predicate field cannot fabricate it.
        let mut incomplete = catalog.clone();
        if let ProfileShape::Object { fields } = &mut incomplete.model.shape {
            fields.remove("pinned");
        }
        let mut missing = raw();
        for entry in missing["models"]["models"].as_array_mut().unwrap() {
            entry.as_object_mut().unwrap().remove("pinned");
        }
        assert!(
            !ProfileSnapshot::capture(missing, &incomplete)
                .unwrap()
                .prestop(&health())
                .ps1
        );
    }

    #[test]
    fn named_scope_guard_denies_distributed_state_and_missing_or_wrong_types() {
        let catalog = catalog();
        for (pointer, value) in [
            (
                "/global_settings/server/distributed_inference_active",
                json!(true),
            ),
            (
                "/global_settings/server/distributed_inference_enabled",
                json!(true),
            ),
            ("/models/models/0/distributed", json!(true)),
            ("/models/models/1/distributed", json!(true)),
            ("/models/models/0/cluster", json!({})),
            (
                "/models/models/1/cluster",
                json!({"SYNTHETIC-REMOTE": "SYNTHETIC-ENDPOINT"}),
            ),
            ("/models/models/1/cluster", json!(false)),
        ] {
            let mut changed = raw();
            *changed.pointer_mut(pointer).unwrap() = value;
            let report = ProfileSnapshot::capture(changed, &catalog)
                .unwrap()
                .prestop(&health());
            assert!(!report.ps6);
            assert!(!report.passed());
        }
        let mut active_only = raw();
        active_only["global_settings"]["server"]["distributed_inference_active"] = json!(true);
        assert!(compare(raw(), active_only, &catalog).equal);
        // Test the predicate itself under a synthetic schema admitting absence
        // and arbitrary types: it must not rely on type validation for safety.
        for field in [
            "distributed_inference_active",
            "distributed_inference_enabled",
            "distributed",
            "cluster",
        ] {
            let mut permissive = catalog.clone();
            let global = field.starts_with("distributed_inference_");
            let target = if global {
                match &mut permissive.global_settings.shape {
                    ProfileShape::Object { fields } => &mut fields.get_mut("server").unwrap().shape,
                    _ => unreachable!(),
                }
            } else {
                &mut permissive.model.shape
            };
            if let ProfileShape::Object { fields } = target {
                fields.insert(
                    field.into(),
                    ProfileRule {
                        required: false,
                        comparison: ComparisonMode::Private,
                        shape: ProfileShape::OpaqueJson {},
                    },
                );
            }
            for replacement in [None, Some(json!("SYNTHETIC-WRONG-TYPE"))] {
                let mut changed = raw();
                let target = if global {
                    &mut changed["global_settings"]["server"]
                } else {
                    &mut changed["models"]["models"][1]
                };
                if let Some(value) = replacement {
                    target[field] = value;
                } else {
                    target.as_object_mut().unwrap().remove(field);
                }
                assert!(
                    !ProfileSnapshot::capture(changed, &permissive)
                        .unwrap()
                        .prestop(&health())
                        .ps6
                );
            }
        }
    }

    #[test]
    fn object_maps_are_typed_private_and_never_export_dynamic_keys() {
        let catalog = catalog();
        let mut changed = raw();
        changed["global_settings"]["map"] = json!({"SYNTHETIC-OTHER-KEY": "SYNTHETIC-MAP-VALUE"});
        let report = compare(raw(), changed, &catalog);
        assert!(!report.fields["/global_settings/map"]);
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("SYNTHETIC")
        );
        let mut wrong_value = raw();
        wrong_value["global_settings"]["map"] = json!({"SYNTHETIC-DYNAMIC": 1});
        assert!(ProfileSnapshot::capture(wrong_value, &catalog).is_err());
        let mut wrong_container = raw();
        wrong_container["global_settings"]["map"] = json!([]);
        assert!(ProfileSnapshot::capture(wrong_container, &catalog).is_err());
    }

    #[test]
    fn virtual_inventory_requires_exact_identity_discriminator_and_null_types() {
        let mut catalog = catalog();
        catalog.virtual_model_id = Some("virtual".into());
        catalog.virtual_model = Some(object(vec![
            (
                "id",
                rule(ProfileShape::Enum {
                    values: vec!["virtual".into()],
                }),
            ),
            ("virtual", rule(ProfileShape::Boolean {})),
            ("fixed_null", rule(ProfileShape::Null {})),
        ]));
        let mut with_virtual = raw();
        with_virtual["models"]["models"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"virtual", "virtual":true, "fixed_null":null}));
        let snapshot = ProfileSnapshot::capture(with_virtual.clone(), &catalog).unwrap();
        assert!(snapshot.summary().virtual_model_present);
        assert_eq!(snapshot.summary().model_count, 2);
        assert!(snapshot.prestop(&health()).passed());
        let report = compare(raw(), with_virtual.clone(), &catalog);
        assert!(!report.model_inventory_equal);
        assert!(!report.fields["/models_by_id/virtual"]);
        for (field, value) in [
            ("virtual", json!(false)),
            ("fixed_null", json!(false)),
            ("id", json!("SYNTHETIC-UNKNOWN")),
        ] {
            let mut invalid = with_virtual.clone();
            invalid["models"]["models"][2][field] = value;
            assert!(ProfileSnapshot::capture(invalid, &catalog).is_err());
        }
    }

    #[test]
    fn catalog_bounds_and_capture_binding_prevent_reclassification() {
        let catalog = catalog();
        let snapshot = ProfileSnapshot::capture(raw(), &catalog).unwrap();
        let other = ProfileSnapshot::capture(raw(), &catalog).unwrap();
        let mut changed = catalog.clone();
        changed.coverage_review_reference = "another-review".into();
        assert!(snapshot.compare(&other, &changed).is_err());
        let mut invalid = catalog.clone();
        invalid.model_ids.push("alpha".into());
        assert!(invalid.validate().is_err());
        let mut invalid = catalog.clone();
        invalid.virtual_model_id = Some("virtual".into());
        assert!(invalid.validate().is_err());
        let mut invalid = catalog.clone();
        invalid.global_settings.shape = ProfileShape::OpaqueJson {};
        assert!(invalid.validate().is_err());
        let mut invalid = catalog.clone();
        if let ProfileShape::Object { fields } = &mut invalid.global_settings.shape {
            fields.insert(
                "public_secret".into(),
                ProfileRule {
                    required: false,
                    comparison: ComparisonMode::Public,
                    shape: ProfileShape::String {},
                },
            );
        }
        assert!(invalid.validate().is_err());
        let mut invalid = catalog.clone();
        let mut deep = ProfileShape::Boolean {};
        for _ in 0..=MAX_DEPTH {
            deep = ProfileShape::Array {
                items: Box::new(rule(deep)),
            };
        }
        if let ProfileShape::Object { fields } = &mut invalid.global_settings.shape {
            fields.insert("deep".into(), rule(deep));
        }
        assert!(invalid.validate().is_err());
        for kind in [
            "null",
            "boolean",
            "integer",
            "number",
            "string",
            "opaque_json",
        ] {
            let malformed = json!({"kind":kind, "unexpected":true});
            assert!(serde_json::from_value::<ProfileShape>(malformed).is_err());
        }
    }
}
