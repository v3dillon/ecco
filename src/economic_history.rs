//! Portable semantic evidence projection, independent of any hosted risk model.
//! Pins and claim admission come from the caller's policy, never from a proof itself.
use crate::{
    economic,
    evidence::{Bundle, Origin},
    federation::{self, digest},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// An admitted origin plus the claim types the caller trusts it to observe.
#[derive(Clone, Deserialize, Serialize)]
pub struct Pin {
    #[serde(flatten)]
    pub origin: Origin,
    #[serde(default)]
    pub claims: Vec<String>,
    #[serde(default)]
    pub suppressed: bool,
}

struct Record<'a> {
    bundle: &'a Bundle,
    pin: &'a Pin,
}

impl Record<'_> {
    fn event(&self) -> &Value {
        &self.bundle.env.body["economic"]
    }
    fn payload(&self) -> &Value {
        &self.event()["payload"]
    }
    fn kind(&self) -> &str {
        self.event()["type"].as_str().unwrap_or("")
    }
    fn time(&self) -> u64 {
        self.bundle.receipt.received_at
    }
    fn id(&self) -> &str {
        &self.bundle.env.id
    }
    fn root(&self) -> &str {
        &self.bundle.profile.root
    }
    fn links(&self) -> Vec<&str> {
        strings(&self.event()["links"])
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Epoch {
    head: String,
    controller: String,
    owner: String,
    owner_epoch: u64,
    effective_at: u64,
}

/// Controller lineage of one `identity_created` entity.
#[derive(Clone, Serialize)]
struct Entity {
    id: String,
    controller: String,
    owner: String,
    head: String,
    epoch: u64,
    status: String,
    history: Vec<Epoch>,
}

fn root_entity(root: &str) -> String {
    format!("ecco:root:{root}")
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .map(|v| v.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn recovery_notice(
    records: &[Record<'_>],
    candidate: &Record<'_>,
    state: &Entity,
    recovery: &Value,
) -> bool {
    let p = candidate.payload();
    let window = recovery["delaySeconds"].as_u64().unwrap_or(0)
        + recovery["contestSeconds"].as_u64().unwrap_or(0);
    if window == 0 && p.get("notice").is_none() {
        return true;
    }
    let Some(notice_id) = p["notice"].as_str() else {
        return false;
    };
    let Some(notice) = records.iter().find(|r| r.id() == notice_id) else {
        return false;
    };
    let n = notice.payload();
    if notice.kind() != "external_attestation"
        || n["claim"] != "ecco.recovery-notice/v1"
        || n["entity"] != state.id
        || n["previous"] != state.head
        || n["controller"] != p["controller"]
        || n["owner"] != state.owner
        || notice.bundle.env.key != p["controller"]
        || notice.root() != p["controller"]
        || !candidate.links().contains(&notice_id)
        || candidate.time() < notice.time().saturating_add(window)
    {
        return false;
    }
    let keys = strings(&recovery["keys"]);
    !records.iter().any(|r| {
        r.kind() == "external_attestation"
            && r.payload()["claim"] == "ecco.recovery-contest/v1"
            && r.payload()["entity"] == state.id
            && r.payload()["notice"] == notice_id
            && r.links().contains(&notice_id)
            && r.bundle.env.key == r.root()
            && (r.root() == state.controller || keys.contains(&r.root()))
            && r.time() >= notice.time()
            && r.time() <= notice.time().saturating_add(window)
            && r.time() <= candidate.time()
    })
}

fn transition(
    record: &Record<'_>,
    state: &Entity,
    recovery: &Value,
    records: &[Record<'_>],
) -> bool {
    let p = record.payload();
    let Some(controller) = p["controller"].as_str() else {
        return false;
    };
    let owner = if record.kind() == "ownership_transferred" {
        root_entity(controller)
    } else {
        state.owner.clone()
    };
    let mut statement = json!({
        "schema": "ecco.controller-transition/v1",
        "entity": state.id,
        "previous": state.head,
        "controller": controller,
        "owner": owner,
    });
    if record.kind() == "identity_recovered" {
        if let Some(notice) = p["notice"].as_str() {
            statement["notice"] = json!(notice);
        }
        if !recovery_notice(records, record, state, recovery) {
            return false;
        }
    }
    if p.get("owner").is_some_and(|v| v != &owner)
        || record.time() <= state.history.last().unwrap().effective_at
        || federation::verify(
            &statement,
            controller,
            p["endorsement"].as_str().unwrap_or(""),
        )
        .is_err()
    {
        return false;
    }
    if record.kind() != "identity_recovered" {
        return record.bundle.env.key == state.controller && record.root() == state.controller;
    }
    let Some(threshold) = recovery["threshold"].as_u64().filter(|n| *n > 0) else {
        return false;
    };
    let keys = strings(&recovery["keys"]);
    let Some(proofs) = p["recoveryEndorsements"].as_array() else {
        return false;
    };
    let mut voters = BTreeSet::new();
    for proof in proofs {
        let key = proof["key"].as_str().unwrap_or("");
        if !keys.contains(&key)
            || federation::verify(&statement, key, proof["sig"].as_str().unwrap_or("")).is_err()
        {
            return false;
        }
        voters.insert(key);
    }
    record.bundle.env.key == controller && voters.len() as u64 >= threshold
}

fn identities(records: &[Record<'_>]) -> BTreeMap<String, Entity> {
    let mut states = BTreeMap::new();
    for inception in records.iter().filter(|r| r.kind() == "identity_created") {
        let root = inception.root();
        let id = format!("ecco:entity:{}", inception.id());
        let owner = root_entity(root);
        let first = Epoch {
            head: inception.id().into(),
            controller: root.into(),
            owner: owner.clone(),
            owner_epoch: 0,
            effective_at: inception.time(),
        };
        let mut state = Entity {
            id: id.clone(),
            controller: root.into(),
            owner,
            head: first.head.clone(),
            epoch: 0,
            status: "verified".into(),
            history: vec![first],
        };
        for _ in 0..records.len() {
            let next: Vec<_> = records
                .iter()
                .filter(|r| {
                    ["key_rotated", "identity_recovered", "ownership_transferred"]
                        .contains(&r.kind())
                        && r.event()["principal"] == id
                        && r.payload()["previous"] == state.head
                        && transition(r, &state, &inception.payload()["recovery"], records)
                })
                .collect();
            if next.len() != 1 {
                if next.len() > 1 {
                    state.status = "contested".into();
                }
                break;
            }
            let next = next[0];
            state.controller = next.payload()["controller"].as_str().unwrap().into();
            if next.kind() == "ownership_transferred" {
                state.owner = root_entity(&state.controller);
                state.epoch += 1;
            }
            state.head = next.id().into();
            state.history.push(Epoch {
                head: state.head.clone(),
                controller: state.controller.clone(),
                owner: state.owner.clone(),
                owner_epoch: state.epoch,
                effective_at: next.time(),
            });
        }
        states.insert(id, state);
    }
    states
}

fn actor(record: &Record<'_>, states: &BTreeMap<String, Entity>) -> Option<String> {
    let root = root_entity(record.root());
    let Some(principal) = record.event()["principal"].as_str() else {
        return Some(root);
    };
    if principal == root {
        return Some(root);
    }
    let state = states.get(principal)?;
    if state.status != "verified" {
        return None;
    }
    let i = state
        .history
        .iter()
        .position(|h| record.event()["controllerHead"] == h.head)?;
    let epoch = &state.history[i];
    if epoch.controller != record.root()
        || record.time() < epoch.effective_at
        || state
            .history
            .get(i + 1)
            .is_some_and(|h| record.time() >= h.effective_at)
    {
        return None;
    }
    Some(format!("{}/owner/{}", state.id, epoch.owner_epoch))
}

fn payment_key(record: &Record<'_>) -> Option<String> {
    if ![
        "payment_authorized",
        "payment_settled",
        "refund",
        "chargeback",
    ]
    .contains(&record.kind())
        || !record.pin.claims.iter().any(|c| c == record.kind())
    {
        return None;
    }
    let source = &record.payload()["source"];
    if source["environment"] != "live" || source["observer"] != root_entity(record.root()) {
        return None;
    }
    let key = json!({
        "provider": source["provider"],
        "account": source["account"],
        "environment": source["environment"],
        "objectId": source["objectId"],
        "type": record.kind(),
    });
    Some(key.to_string())
}

/// Reproduce attribution, continuity, authority revocation and conflicting economic assertions.
/// No maturity, solvency, loss probability or objective fulfillment judgment is returned.
fn procedural_dispute(
    id: &str,
    t: &Value,
    related: &[&Record<'_>],
    states: &BTreeMap<String, Entity>,
) -> Value {
    let policy = &t["disputePolicy"];
    let rows: Vec<_> = related
        .iter()
        .copied()
        .filter(|r| {
            r.payload()["disputeId"] == id
                && r.payload()["termsDigest"] == t["termsDigest"]
                && r.payload()["procedureDigest"] == policy["procedureDigest"]
        })
        .collect();
    let party =
        |r: &Record<'_>| actor(r, states).is_some_and(|a| t["buyer"] == a || t["seller"] == a);
    let linked =
        |r: &Record<'_>, p: &Record<'_>| r.links().contains(&p.id()) && r.time() >= p.time();
    let opened: Vec<_> = rows
        .iter()
        .copied()
        .filter(|r| {
            r.kind() == "dispute_opened" && r.payload().get("appeals").is_none() && party(r)
        })
        .collect();
    let initial: Vec<_> = rows
        .iter()
        .copied()
        .filter(|r| {
            r.kind() == "dispute_resolved"
                && r.payload().get("previousResolution").is_none()
                && r.payload().get("appeal").is_none()
                && actor(r, states).is_some_and(|a| t["arbiter"] == a)
                && opened.iter().any(|o| linked(r, o))
        })
        .collect();
    let ids = |rs: &[&Record<'_>]| {
        rs.iter()
            .map(|r| r.id().to_string())
            .collect::<BTreeSet<_>>()
    };
    let mut result = json!({
        "id": id,
        "opened": ids(&opened),
        "outcomes": [],
        "resolutionHistory": ids(&initial),
        "appeals": [],
        "finalAfter": 0,
        "contested": initial.len() > 1,
    });
    if initial.len() != 1 {
        return result;
    }
    let first = initial[0];
    let deadline = first.time() + policy["appealWindowSeconds"].as_u64().unwrap();
    result["finalAfter"] = json!(deadline);
    let appeals: Vec<_> = rows
        .iter()
        .copied()
        .filter(|r| {
            r.kind() == "dispute_opened"
                && r.payload()["appeals"] == first.id()
                && party(r)
                && linked(r, first)
                && r.time() <= deadline
        })
        .collect();
    result["appeals"] = json!(ids(&appeals));
    let finals: Vec<_> = rows
        .iter()
        .copied()
        .filter(|r| {
            r.kind() == "dispute_resolved"
                && actor(r, states).is_some_and(|a| policy["appealArbiter"] == a)
                && r.payload()["previousResolution"] == first.id()
                && linked(r, first)
                && appeals.iter().all(|a| linked(r, a))
                && appeals
                    .iter()
                    .any(|a| r.payload()["appeal"] == a.id() && linked(r, a))
        })
        .collect();
    let mut history = ids(&initial);
    history.extend(ids(&finals));
    result["resolutionHistory"] = json!(history);
    result["contested"] = json!(finals.len() > 1);
    let effective = if appeals.is_empty() {
        initial
    } else if finals.len() == 1 {
        finals
    } else {
        vec![]
    };
    result["outcomes"] = json!(effective
        .iter()
        .filter_map(|r| r.payload()["outcome"].as_str())
        .collect::<BTreeSet<_>>());
    result
}

pub fn project(bundles: &[Bundle], pins: &[Pin]) -> Result<Value, String> {
    if bundles.len() > 10000 {
        return Err("semantic evidence limit exceeded".into());
    }
    let mut admitted = BTreeMap::new();
    let mut suppressed = BTreeSet::new();
    for bundle in bundles {
        if !bundle.env.body["economic"].is_object() {
            return Err("economic event required".into());
        }
        let pin = pins
            .iter()
            .find(|p| p.origin.matches(bundle))
            .ok_or("independently admitted origin required")?;
        bundle.verify_trusted(&pin.origin.root, &pin.origin.relay)?;
        economic::verify_assertion(&bundle.env, &bundle.profile, bundle.receipt.received_at)?;
        if pin.suppressed {
            suppressed.insert(bundle.env.id.clone());
            continue;
        }
        admitted.insert(bundle.env.id.clone(), Record { bundle, pin });
    }
    let mut records: Vec<_> = admitted.into_values().collect();
    let revoked: BTreeSet<String> = records
        .iter()
        .filter(|r| r.bundle.env.key != r.root())
        .filter(|r| {
            records.iter().any(|v| {
                v.kind() == "delegation_revoked"
                    && v.root() == r.root()
                    && v.time() <= r.time()
                    && v.payload()["grantId"] == digest(&r.event()["grant"])
            })
        })
        .map(|r| r.id().to_string())
        .collect();
    suppressed.extend(revoked.iter().cloned());
    records.retain(|r| !revoked.contains(r.id()));
    let states = identities(&records);
    let actors: BTreeMap<_, _> = records
        .iter()
        .map(|r| (r.id().to_string(), actor(r, &states)))
        .collect();
    let mut attribution: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
    for r in &records {
        if let Some(key) = payment_key(r) {
            attribution.entry(key).or_default().insert((
                r.event()["interaction"].to_string(),
                r.payload()["amount"].to_string(),
            ));
        }
    }
    let mut views = Vec::new();
    for opening in records.iter().filter(|r| r.kind() == "interaction_started") {
        let id = opening.id();
        let t = opening.payload();
        let related: Vec<_> = records
            .iter()
            .filter(|r| r.id() == id || r.event()["interaction"] == id)
            .collect();
        let mut accepted = BTreeSet::new();
        let mut deliveries = BTreeSet::new();
        let mut acknowledgments = BTreeSet::new();
        let mut rejections = BTreeSet::new();
        let mut payments = BTreeSet::new();
        let mut disputes: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
        for r in &related {
            let Some(a) = actor(r, &states) else {
                continue;
            };
            let p = r.payload();
            let party = t["buyer"] == a || t["seller"] == a;
            if ["interaction_started", "offer_accepted"].contains(&r.kind())
                && party
                && p["termsDigest"] == t["termsDigest"]
                && (t.get("disputePolicy").is_none()
                    || r.kind() == "interaction_started"
                    || p["disputePolicyDigest"] == digest(&t["disputePolicy"]))
            {
                accepted.insert(a.clone());
            }
            if r.kind() == "artifact_delivered"
                && t["seller"] == a
                && p["termsDigest"] == t["termsDigest"]
                && strings(&t["milestones"]).contains(&p["milestone"].as_str().unwrap_or(""))
            {
                deliveries.insert(r.id());
            }
            if ["fulfillment_acknowledged", "fulfillment_rejected"].contains(&r.kind())
                && t["buyer"] == a
                && p["termsDigest"] == t["termsDigest"]
                && strings(&t["milestones"]).contains(&p["milestone"].as_str().unwrap_or(""))
            {
                let delivered = related.iter().any(|d| {
                    d.kind() == "artifact_delivered"
                        && actor(d, &states).is_some_and(|a| t["seller"] == a)
                        && d.payload()["termsDigest"] == t["termsDigest"]
                        && d.payload()["artifactDigest"] == p["artifactDigest"]
                        && d.payload()["milestone"] == p["milestone"]
                        && r.links().contains(&d.id())
                });
                if delivered {
                    if r.kind() == "fulfillment_acknowledged" {
                        acknowledgments.insert(r.id());
                    } else {
                        rejections.insert(r.id());
                    }
                }
            }
            if let Some(key) = payment_key(r) {
                if attribution
                    .get(&key)
                    .is_some_and(|values| values.len() == 1)
                {
                    payments.insert(key);
                }
            }
            if ["dispute_opened", "dispute_resolved"].contains(&r.kind()) {
                let d = disputes
                    .entry(p["disputeId"].as_str().unwrap_or("").into())
                    .or_default();
                if r.kind() == "dispute_opened" && party {
                    d.0.insert(r.id().to_string());
                }
                if r.kind() == "dispute_resolved" && t["arbiter"] == a {
                    d.1.insert(p["outcome"].as_str().unwrap_or("").into());
                }
            }
        }
        let mut provider_states: BTreeMap<String, (u64, BTreeSet<String>)> = BTreeMap::new();
        for r in &related {
            let p = r.payload();
            let source = &p["source"];
            let observed = match p.get("observedAt") {
                None => Some(r.time()),
                Some(v) => v.as_u64(),
            };
            let Some(time) = observed.filter(|t| *t <= r.time()) else {
                continue;
            };
            if r.kind() != "external_attestation"
                || p["claim"] != "stripe_dispute_status"
                || !r.pin.claims.iter().any(|c| c == "stripe_dispute_status")
                || source["provider"] != "stripe"
                || source["environment"] != "live"
                || source["observer"] != root_entity(r.root())
                || !economic::text(&source["account"])
                || !economic::text(&source["objectId"])
                || !economic::text(&p["status"])
            {
                continue;
            }
            let key = json!([r.root(), source["account"], source["objectId"]]).to_string();
            let state = provider_states
                .entry(key)
                .or_insert_with(|| (time, BTreeSet::new()));
            if time > state.0 {
                state.0 = time;
                state.1.clear();
            }
            if time == state.0 {
                state.1.insert(p["status"].as_str().unwrap().to_string());
            }
        }
        let provider_open = provider_states.values().any(|(_, statuses)| {
            statuses
                .iter()
                .any(|s| !["won", "warning_closed"].contains(&s.as_str()))
        });
        let disputed: Vec<_> = disputes
            .into_iter()
            .map(|(id, (opened, outcomes))| {
                if t.get("disputePolicy").is_some() {
                    procedural_dispute(&id, t, &related, &states)
                } else {
                    json!({"id":id,"opened":opened,"outcomes":outcomes})
                }
            })
            .collect();
        views.push(json!({
            "id": id,
            "acceptedBy": accepted,
            "deliveries": deliveries,
            "acknowledgments": acknowledgments,
            "rejections": rejections,
            "paymentKeys": payments,
            "disputes": disputed,
            "providerDisputeOpen": provider_open,
            "fulfillmentConflict": !acknowledgments.is_empty() && !rejections.is_empty(),
        }));
    }
    let mut operating = Vec::new();
    let mut grouped: BTreeMap<String, Vec<&Record<'_>>> = BTreeMap::new();
    for r in records
        .iter()
        .filter(|r| r.kind() == "operating_version_changed")
    {
        if let Some(a) = actor(r, &states) {
            grouped.entry(a).or_default().push(r);
        }
    }
    for (subject, rows) in grouped {
        let mut head = Value::Null;
        let mut version = Value::Null;
        let mut status = "verified";
        let mut history = Vec::new();
        let mut last = None;
        for _ in 0..rows.len() {
            let next: Vec<_> = rows
                .iter()
                .filter(|r| r.payload()["previous"] == head && last.is_none_or(|at| r.time() > at))
                .collect();
            if next.len() != 1 {
                if next.len() > 1 {
                    status = "contested";
                }
                break;
            }
            let r = next[0];
            head = json!(r.id());
            version = r.payload()["versionDigest"].clone();
            last = Some(r.time());
            history.push(json!({"head":head,"version":version,"observedAt":r.time()}));
        }
        if status == "verified" && history.len() != rows.len() {
            status = "incomplete";
        }
        operating.push(json!({
            "subject": subject,
            "head": head,
            "version": version,
            "status": status,
            "history": history,
        }));
    }
    Ok(json!({
        "schema": "ecco.semantic-evidence/v1",
        "identities": states.values().collect::<Vec<_>>(),
        "actors": actors,
        "suppressed": suppressed,
        "interactions": views,
        "operating": operating,
    }))
}
