use anyhow::{anyhow, Context, Result};
use frame_decode::extrinsics::{decode_extrinsic_current, ExtrinsicDecodeError, ExtrinsicOwned};
use frame_metadata::{RuntimeMetadata, RuntimeMetadataPrefixed, META_RESERVED};
use jsonrpsee::{
    core::client::{ClientT, SubscriptionClientT},
    rpc_params,
    ws_client::WsClient,
    ws_client::WsClientBuilder,
};
use parity_scale_codec::{Compact, Decode, Encode};
use scale_value::{Composite, Value, ValueDef};
use scale_value::scale;
use serde::Deserialize;
use sp_crypto_hashing::blake2_256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

const DEFAULT_WS: &str = "wss://entrypoint-finney.opentensor.ai";
const VALIDATION_METHOD: &str = "TaggedTransactionQueue_validate_transaction";

#[derive(Debug)]
struct Config {
    ws_url: String,
    baseline_priority: u64,
    auto_baseline: bool,
}

impl Config {
    fn from_args() -> Result<Self> {
        let mut ws_url = DEFAULT_WS.to_string();
        let mut baseline_priority = 0u64;
        let mut auto_baseline = true;

        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--ws" => {
                    ws_url = args.next().context("--ws requires a value")?;
                }
                "--baseline-priority" => {
                    let val = args.next().context("--baseline-priority requires a value")?;
                    baseline_priority = val.parse().context("invalid --baseline-priority")?;
                }
                "--auto-baseline" => {
                    auto_baseline = true;
                }
                "--no-auto-baseline" => {
                    auto_baseline = false;
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    return Err(anyhow!("unknown argument: {other}"));
                }
            }
        }

        Ok(Config {
            ws_url,
            baseline_priority,
            auto_baseline,
        })
    }
}

fn print_usage() {
    println!(
        "mev-scanner\n\n");
    println!("Usage:");
    println!("  mev-scanner [--ws <WSS_URL>] [--baseline-priority <U64>] [--auto-baseline]");
    println!("\nOptions:");
    println!("  --ws <WSS_URL>              WSS endpoint (default: {DEFAULT_WS})");
    println!("  --baseline-priority <U64>   Priority threshold for staking txs (default: 0)");
    println!("  --auto-baseline             Enable auto baseline (default)");
    println!("  --no-auto-baseline          Disable auto baseline");
    println!("  -h, --help                  Show this help");
}

#[derive(Debug)]
struct Baseline {
    fixed: u64,
    auto: bool,
    per_call_min: HashMap<String, u64>,
}

impl Baseline {
    fn new(fixed: u64, auto: bool) -> Self {
        Self {
            fixed,
            auto,
            per_call_min: HashMap::new(),
        }
    }

    fn check(&mut self, call_key: &str, priority: u64) -> (u64, bool) {
        if !self.auto {
            return (self.fixed, priority > self.fixed);
        }

        let entry = self.per_call_min.entry(call_key.to_string());
        match entry {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(priority);
                (priority, false)
            }
            std::collections::hash_map::Entry::Occupied(mut o) => {
                let baseline = *o.get();
                if priority < baseline {
                    o.insert(priority);
                    (priority, false)
                } else {
                    (baseline, priority > baseline)
                }
            }
        }
    }
}

struct Seen {
    set: HashSet<String>,
    order: VecDeque<String>,
    limit: usize,
}

impl Seen {
    fn new(limit: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
            limit,
        }
    }

    fn insert(&mut self, hash: String) -> bool {
        if !self.set.insert(hash.clone()) {
            return false;
        }
        self.order.push_back(hash);
        if self.order.len() > self.limit {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

struct Stats {
    total_seen: AtomicU64,
    staking_seen: AtomicU64,
    elevated_found: AtomicU64,
    validation_errors: AtomicU64,
    blocks_scanned: AtomicU64,
    last_hash: RwLock<String>,
    tipped_staking: AtomicU64,
    evm_tipped_staking: AtomicU64,
    max_evm_tip: RwLock<u128>,
    min_priority: RwLock<Option<u64>>,
    max_priority: RwLock<Option<u64>>,
}

impl Stats {
    fn inc_total(&self) {
        self.total_seen.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_staking(&self) {
        self.staking_seen.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_elevated(&self) {
        self.elevated_found.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_error(&self) {
        self.validation_errors.fetch_add(1, Ordering::Relaxed);
    }

    async fn note_head(&self, hash: &str) {
        let mut guard = self.last_hash.write().await;
        if guard.as_str() != hash {
            *guard = hash.to_string();
            self.blocks_scanned.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn note_tip(&self, tip: u128) {
        if tip == 0 {
            return;
        }
        self.tipped_staking.fetch_add(1, Ordering::Relaxed);
    }

    async fn note_evm_tip(&self, tip: u128) {
        if tip == 0 {
            return;
        }
        self.evm_tipped_staking.fetch_add(1, Ordering::Relaxed);
        let mut max = self.max_evm_tip.write().await;
        if tip > *max {
            *max = tip;
        }
    }

    async fn note_priority(&self, priority: u64) {
        let mut min = self.min_priority.write().await;
        let mut max = self.max_priority.write().await;
        match *min {
            Some(v) if priority < v => *min = Some(priority),
            None => *min = Some(priority),
            _ => {}
        }
        match *max {
            Some(v) if priority > v => *max = Some(priority),
            None => *max = Some(priority),
            _ => {}
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            total_seen: AtomicU64::new(0),
            staking_seen: AtomicU64::new(0),
            elevated_found: AtomicU64::new(0),
            validation_errors: AtomicU64::new(0),
            blocks_scanned: AtomicU64::new(0),
            last_hash: RwLock::new(String::new()),
            tipped_staking: AtomicU64::new(0),
            evm_tipped_staking: AtomicU64::new(0),
            max_evm_tip: RwLock::new(0),
            min_priority: RwLock::new(None),
            max_priority: RwLock::new(None),
        }
    }
}

#[derive(Debug)]
struct DecodedExtrinsic {
    bytes: Vec<u8>,
    ext: ExtrinsicOwned<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_args()?;

    let client = Arc::new(
        WsClientBuilder::default()
            .build(&config.ws_url)
            .await
            .context("failed to connect to ws endpoint")?,
    );

    let metadata = Arc::new(fetch_metadata(&client).await?);
    let head_state = Arc::new(RwLock::new(fetch_head_state(&client).await?));

    let updater_client = Arc::clone(&client);
    let updater_head_state = Arc::clone(&head_state);
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(6));
        loop {
            ticker.tick().await;
            if let Ok(state) = fetch_head_state(&updater_client).await {
                *updater_head_state.write().await = state;
            }
        }
    });

    let mut baseline = Baseline::new(config.baseline_priority, config.auto_baseline);
    let mut seen = Seen::new(2048);
    let stats = Arc::new(Stats::default());

    println!(
        "Connected to {}. Watching pending extrinsics...",
        config.ws_url
    );


    match client
        .subscribe::<String, _>(
            "author_subscribePendingExtrinsics",
            rpc_params![],
            "author_unsubscribePendingExtrinsics",
        )
        .await
    {
        Ok(mut subscription) => {
            while let Some(message) = subscription.next().await {
                let hex = match message {
                    Ok(value) => value,
                    Err(err) => {
                        eprintln!("subscription error: {err}");
                        continue;
                    }
                };
                process_extrinsic(
                    &client,
                    &metadata,
                    &head_state,
                    &mut baseline,
                    &mut seen,
                    &stats,
                    hex,
                )
                .await;
            }
        }
        Err(err) => {
            let err_msg = err.to_string();
            if err_msg.contains("Method not found") {
                eprintln!(
                    "Subscription not supported; falling back to polling (author_pendingExtrinsics)."
                );
                poll_pending_extrinsics(
                    &client,
                    &metadata,
                    &head_state,
                    &mut baseline,
                    &mut seen,
                    &stats,
                )
                .await?;
            } else {
                return Err(anyhow!(err));
            }
        }
    }

    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

async fn poll_pending_extrinsics(
    client: &WsClient,
    metadata: &RuntimeMetadata,
    head_state: &Arc<RwLock<HeadState>>,
    baseline: &mut Baseline,
    seen: &mut Seen,
    stats: &Arc<Stats>,
) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(2));
    loop {
        ticker.tick().await;
        let pending: Vec<String> = client
            .request("author_pendingExtrinsics", rpc_params![])
            .await
            .context("author_pendingExtrinsics failed")?;

        for hex in pending {
            process_extrinsic(
                client,
                metadata,
                head_state,
                baseline,
                seen,
                stats,
                hex,
            )
            .await;
        }
    }
}

async fn process_extrinsic(
    client: &WsClient,
    metadata: &RuntimeMetadata,
    head_state: &Arc<RwLock<HeadState>>,
    baseline: &mut Baseline,
    seen: &mut Seen,
    stats: &Arc<Stats>,
    hex: String,
) {
    let raw_bytes = match decode_hex(&hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("failed to decode extrinsic hex: {err}");
            return;
        }
    };

    let hash_hex = format!("0x{}", hex::encode(blake2_256(&raw_bytes)));
    if !seen.insert(hash_hex.clone()) {
        return;
    }
    stats.inc_total();
    let head = { head_state.read().await.clone() };
    stats.note_head(&head.hash).await;

    let decoded = match decode_extrinsic(metadata, &raw_bytes) {
        Ok(ext) => ext,
        Err(err) => {
            stats.inc_error();
            log_error_line(
                head_state,
                &format!("decode_failed tx={hash_hex} err={err}"),
            )
            .await;
            print_status_line_once(stats, head_state).await;
            return;
        }
    };

    let top_call = format!("{}::{}", decoded.ext.pallet_name(), decoded.ext.call_name());
    let top_is_stake = is_stake_name(decoded.ext.call_name());

    let mut nested_paths = find_stake_paths_in_args(metadata, &decoded);
    nested_paths.sort();
    nested_paths.dedup();

    if !top_is_stake && nested_paths.is_empty() {
        print_status_line_once(stats, head_state).await;
        return;
    }

    stats.inc_staking();
    stats.note_head(&head.hash).await;
    let tip = extract_tip(metadata, &decoded, &decoded.bytes).unwrap_or(0);
    let evm_tip = extract_evm_tip(metadata, &decoded, &decoded.bytes).unwrap_or(0);
    stats.note_tip(tip).await;
    stats.note_evm_tip(evm_tip).await;

    match validate_transaction(client, &head.hash, &decoded.bytes).await {
        Ok(valid) => {
            stats.note_priority(valid.priority).await;
            let (baseline_val, elevated) = baseline.check(&top_call, valid.priority);
            if elevated {
                stats.inc_elevated();
            }

            if elevated || tip > 0 || evm_tip > 0 {
                let ts = now_unix();
                let blocks_scanned = stats.blocks_scanned.load(Ordering::Relaxed);
                println!(
                    "[{ts}] tx={hash_hex} top={top_call} priority={} baseline={baseline_val} tip={tip} evm_tip={evm_tip} elevated={elevated} requires={} provides={} longevity={} propagate={} block={} spec_version={} blocks_scanned={} nested={}",
                    valid.priority,
                    format_tags(&valid.requires),
                    format_tags(&valid.provides),
                    valid.longevity,
                    valid.propagate,
                    head.number,
                    head.spec_version,
                    blocks_scanned,
                    if nested_paths.is_empty() {
                        "-".to_string()
                    } else {
                        nested_paths.join(",")
                    }
                );
            } else {
                print_status_line_once(stats, head_state).await;
            }
        }
        Err(err) => {
            stats.inc_error();
            log_error_line(
                head_state,
                &format!("validation_failed tx={hash_hex} top={top_call} err={err}"),
            )
            .await;
            print_status_line_once(stats, head_state).await;
        }
    }
}

async fn print_status_line_once(stats: &Stats, head_state: &Arc<RwLock<HeadState>>) {
    let total = stats.total_seen.load(Ordering::Relaxed);
    let staking = stats.staking_seen.load(Ordering::Relaxed);
    let elevated = stats.elevated_found.load(Ordering::Relaxed);
    let errors = stats.validation_errors.load(Ordering::Relaxed);
    let tipped = stats.tipped_staking.load(Ordering::Relaxed);
    let evm_tipped = stats.evm_tipped_staking.load(Ordering::Relaxed);
    let max_evm_tip = { *stats.max_evm_tip.read().await };
    let min_priority = { *stats.min_priority.read().await };
    let max_priority = { *stats.max_priority.read().await };
    let head = { head_state.read().await.clone() };
    stats.note_head(&head.hash).await;
    let blocks_scanned = stats.blocks_scanned.load(Ordering::Relaxed);
    let line = format!(
        "\rblock={} spec_version={} blocks_scanned={} seen={} staking={} tipped={} evm_tipped={} max_evm_tip={} min_priority={} max_priority={} elevated={} errors={}   ",
        head.number,
        head.spec_version,
        blocks_scanned,
        total,
        staking,
        tipped,
        evm_tipped,
        max_evm_tip,
        min_priority.unwrap_or(0),
        max_priority.unwrap_or(0),
        elevated,
        errors
    );
    let _ = std::io::stdout().write_all(line.as_bytes());
    let _ = std::io::stdout().flush();
}

async fn log_error_line(head_state: &Arc<RwLock<HeadState>>, message: &str) {
    let ts = now_unix();
    let head = { head_state.read().await.clone() };
    println!(
        "[{ts}] error={message} block={} spec_version={}",
        head.number, head.spec_version
    );
}

#[derive(Clone, Debug)]
struct HeadState {
    hash: String,
    number: u64,
    spec_version: u32,
}

#[derive(Deserialize)]
struct RuntimeVersionRpc {
    #[serde(rename = "specVersion")]
    spec_version: u32,
}

#[derive(Deserialize)]
struct HeaderRpc {
    number: String,
}

async fn fetch_head_state(client: &WsClient) -> Result<HeadState> {
    let hash: String = client
        .request("chain_getBlockHash", rpc_params![])
        .await
        .context("chain_getBlockHash failed")?;
    let header = fetch_header(client, &hash).await?;
    let spec_version = fetch_runtime_spec_version(client).await?;
    Ok(HeadState {
        hash,
        number: header,
        spec_version,
    })
}

async fn fetch_header(client: &WsClient, hash: &str) -> Result<u64> {
    let header: HeaderRpc = client
        .request("chain_getHeader", rpc_params![hash])
        .await
        .context("chain_getHeader failed")?;
    parse_hex_u64(&header.number)
}

async fn fetch_runtime_spec_version(client: &WsClient) -> Result<u32> {
    let version: RuntimeVersionRpc = client
        .request("state_getRuntimeVersion", rpc_params![])
        .await
        .context("state_getRuntimeVersion failed")?;
    Ok(version.spec_version)
}

fn parse_hex_u64(value: &str) -> Result<u64> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(trimmed, 16).context("invalid hex number")
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    Ok(hex::decode(trimmed)?)
}

fn decode_extrinsic(metadata: &RuntimeMetadata, raw_bytes: &[u8]) -> Result<DecodedExtrinsic> {
    if !matches!(
        metadata,
        RuntimeMetadata::V14(_) | RuntimeMetadata::V15(_) | RuntimeMetadata::V16(_)
    ) {
        return Err(anyhow!("unsupported metadata version"));
    }

    match decode_extrinsic_inner(metadata, raw_bytes) {
        Ok(ext) => Ok(DecodedExtrinsic {
            bytes: raw_bytes.to_vec(),
            ext,
        }),
        Err(err) => {
            // Try prefixing length for nodes that return raw bytes without length.
            if !matches!(
                err,
                ExtrinsicDecodeError::CannotDecodeLength
                    | ExtrinsicDecodeError::WrongLength { .. }
                    | ExtrinsicDecodeError::NotEnoughBytes
            ) {
                return Err(anyhow!(err.to_string()));
            }
            let mut prefixed = Vec::new();
            Compact(raw_bytes.len() as u64).encode_to(&mut prefixed);
            prefixed.extend_from_slice(raw_bytes);
            let ext = decode_extrinsic_inner(metadata, &prefixed)?;
            Ok(DecodedExtrinsic {
                bytes: prefixed,
                ext,
            })
        }
    }
}

fn decode_extrinsic_inner(
    metadata: &RuntimeMetadata,
    bytes: &[u8],
) -> std::result::Result<ExtrinsicOwned<u32>, ExtrinsicDecodeError> {
    let mut cursor = bytes;
    let ext = match metadata {
        RuntimeMetadata::V14(meta) => decode_extrinsic_current(&mut cursor, meta)?,
        RuntimeMetadata::V15(meta) => decode_extrinsic_current(&mut cursor, meta)?,
        RuntimeMetadata::V16(meta) => decode_extrinsic_current(&mut cursor, meta)?,
        _ => unreachable!("metadata version checked before call"),
    };

    Ok(ext.into_owned())
}

fn is_stake_name(name: &str) -> bool {
    name.to_ascii_lowercase().contains("stake")
}

fn find_stake_paths_in_args(metadata: &RuntimeMetadata, decoded: &DecodedExtrinsic) -> Vec<String> {
    let mut matches = Vec::new();
    for arg in decoded.ext.call_data() {
        let range = arg.range();
        if range.end > decoded.bytes.len() {
            continue;
        }
        let arg_bytes = &decoded.bytes[range];
        if let Ok(value) = decode_value(metadata, *arg.ty(), arg_bytes) {
            let mut path = Vec::new();
            collect_stake_paths(&value, &mut path, &mut matches);
        }
    }
    matches
}

fn decode_value(metadata: &RuntimeMetadata, ty_id: u32, bytes: &[u8]) -> Result<Value<()>> {
    match metadata {
        RuntimeMetadata::V14(meta) => {
            let value = scale::decode_as_type(&mut &*bytes, ty_id, &meta.types)?;
            Ok(value.remove_context())
        }
        RuntimeMetadata::V15(meta) => {
            let value = scale::decode_as_type(&mut &*bytes, ty_id, &meta.types)?;
            Ok(value.remove_context())
        }
        RuntimeMetadata::V16(meta) => {
            let value = scale::decode_as_type(&mut &*bytes, ty_id, &meta.types)?;
            Ok(value.remove_context())
        }
        _ => Err(anyhow!("unsupported metadata version")),
    }
}

fn collect_stake_paths(value: &Value<()>, path: &mut Vec<String>, matches: &mut Vec<String>) {
    match &value.value {
        ValueDef::Variant(variant) => {
            path.push(variant.name.clone());
            if is_stake_name(&variant.name) && path.len() >= 2 {
                matches.push(path.join("::"));
            }
            collect_from_composite(&variant.values, path, matches);
            path.pop();
        }
        ValueDef::Composite(composite) => {
            collect_from_composite(composite, path, matches);
        }
        _ => {}
    }
}

fn collect_from_composite(composite: &Composite<()>, path: &mut Vec<String>, matches: &mut Vec<String>) {
    match composite {
        Composite::Named(fields) => {
            for (_, value) in fields {
                collect_stake_paths(value, path, matches);
            }
        }
        Composite::Unnamed(values) => {
            for value in values {
                collect_stake_paths(value, path, matches);
            }
        }
    }
}

fn extract_tip(
    metadata: &RuntimeMetadata,
    decoded: &DecodedExtrinsic,
    bytes: &[u8],
) -> Option<u128> {
    let exts = decoded.ext.transaction_extension_payload()?;
    for ext in exts.iter() {
        let range = ext.range();
        if range.end > bytes.len() {
            continue;
        }
        let ext_bytes = &bytes[range];
        let value = decode_value(metadata, *ext.ty(), ext_bytes).ok()?;
        if let Some(tip) = find_tip_in_value(&value) {
            return Some(tip);
        }
    }
    None
}

fn extract_evm_tip(
    metadata: &RuntimeMetadata,
    decoded: &DecodedExtrinsic,
    bytes: &[u8],
) -> Option<u128> {
    let mut max_tip = 0u128;
    let keys = [
        "gas_price",
        "max_priority_fee_per_gas",
        "max_fee_per_gas",
        "gasPrice",
        "maxPriorityFeePerGas",
        "maxFeePerGas",
    ];
    for arg in decoded.ext.call_data() {
        let range = arg.range();
        if range.end > bytes.len() {
            continue;
        }
        let arg_bytes = &bytes[range];
        let value = match decode_value(metadata, *arg.ty(), arg_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let tip = find_named_u128_in_value(&value, &keys);
        if tip > max_tip {
            max_tip = tip;
        }
    }
    if max_tip > 0 {
        Some(max_tip)
    } else {
        None
    }
}

fn find_named_u128_in_value(value: &Value<()>, keys: &[&str]) -> u128 {
    match &value.value {
        ValueDef::Composite(Composite::Named(fields)) => {
            let mut best = 0u128;
            for (name, val) in fields {
                if keys.iter().any(|k| k.eq_ignore_ascii_case(name)) {
                    if let Some(n) = extract_u128(val) {
                        if n > best {
                            best = n;
                        }
                    }
                }
                let sub = find_named_u128_in_value(val, keys);
                if sub > best {
                    best = sub;
                }
            }
            best
        }
        ValueDef::Composite(Composite::Unnamed(values)) => {
            values
                .iter()
                .map(|v| find_named_u128_in_value(v, keys))
                .max()
                .unwrap_or(0)
        }
        ValueDef::Variant(variant) => {
            let wrapped = Value::without_context(ValueDef::Composite(variant.values.clone()));
            find_named_u128_in_value(&wrapped, keys)
        }
        _ => 0,
    }
}

fn find_tip_in_value(value: &Value<()>) -> Option<u128> {
    match &value.value {
        ValueDef::Composite(Composite::Named(fields)) => {
            for (name, val) in fields {
                if name.eq_ignore_ascii_case("tip") {
                    if let Some(tip) = extract_u128(val) {
                        return Some(tip);
                    }
                }
                if let Some(tip) = find_tip_in_value(val) {
                    return Some(tip);
                }
            }
        }
        ValueDef::Composite(Composite::Unnamed(values)) => {
            for val in values {
                if let Some(tip) = find_tip_in_value(val) {
                    return Some(tip);
                }
            }
        }
        ValueDef::Variant(variant) => {
            if let Some(tip) = find_tip_in_value(&Value::without_context(ValueDef::Composite(
                variant.values.clone(),
            ))) {
                return Some(tip);
            }
        }
        _ => {}
    }
    None
}

fn extract_u128(value: &Value<()>) -> Option<u128> {
    match &value.value {
        ValueDef::Primitive(p) => p.as_u128().or_else(|| match p {
            scale_value::Primitive::U256(bytes) => {
                let mut high = [0u8; 16];
                high.copy_from_slice(&bytes[..16]);
                if high.iter().any(|b| *b != 0) {
                    return None;
                }
                let mut low = [0u8; 16];
                low.copy_from_slice(&bytes[16..]);
                Some(u128::from_be_bytes(low))
            }
            scale_value::Primitive::String(s) => {
                let trimmed = s.strip_prefix("0x").unwrap_or(s);
                u128::from_str_radix(trimmed, 16).ok().or_else(|| s.parse::<u128>().ok())
            }
            _ => None,
        }),
        _ => None,
    }
}

async fn fetch_metadata(client: &WsClient) -> Result<RuntimeMetadata> {
    let metadata_hex: String = client
        .request("state_getMetadata", rpc_params![])
        .await
        .context("state_getMetadata failed")?;
    let metadata_bytes = decode_hex(&metadata_hex).context("metadata hex decode failed")?;
    if let Ok(prefixed) = RuntimeMetadataPrefixed::decode(&mut &metadata_bytes[..]) {
        if prefixed.0 == META_RESERVED {
            return Ok(prefixed.1);
        }
    }
    Ok(RuntimeMetadata::decode(&mut &metadata_bytes[..])?)
}


async fn validate_transaction(
    client: &WsClient,
    block_hash_hex: &str,
    extrinsic_bytes: &[u8],
) -> Result<TransactionValid> {
    let block_hash = decode_hash32(block_hash_hex)?;
    let params_v3 = encode_validate_params(extrinsic_bytes, Some(&block_hash));
    if let Ok(response) = state_call(client, VALIDATION_METHOD, &params_v3, block_hash_hex).await {
        if let Ok(result) = decode_validation_result(&response) {
            return match result {
                ValidationResult::Valid(valid) => Ok(valid),
                ValidationResult::Invalid(err) => Err(anyhow!("transaction invalid: {err:?}")),
                ValidationResult::Unknown(err) => Err(anyhow!("transaction unknown: {err:?}")),
            };
        }
    }

    let params_v2 = encode_validate_params(extrinsic_bytes, None);
    let response = state_call(client, VALIDATION_METHOD, &params_v2, block_hash_hex).await?;
    match decode_validation_result(&response)? {
        ValidationResult::Valid(valid) => Ok(valid),
        ValidationResult::Invalid(err) => Err(anyhow!("transaction invalid: {err:?}")),
        ValidationResult::Unknown(err) => Err(anyhow!("transaction unknown: {err:?}")),
    }
}

fn format_tags(tags: &[Vec<u8>]) -> String {
    if tags.is_empty() {
        return "0".to_string();
    }
    let preview: Vec<String> = tags
        .iter()
        .take(3)
        .map(|t| format!("0x{}", hex::encode(t)))
        .collect();
    if tags.len() <= 3 {
        format!("{}", preview.join(","))
    } else {
        format!("{}+{}", preview.join(","), tags.len() - 3)
    }
}

async fn state_call(
    client: &WsClient,
    method: &str,
    params: &[u8],
    at_hash: &str,
) -> Result<Vec<u8>> {
    let data_hex = format!("0x{}", hex::encode(params));
    let response_hex: String = client
        .request("state_call", rpc_params![method, data_hex, at_hash])
        .await
        .context("state_call failed")?;
    decode_hex(&response_hex)
}

fn encode_validate_params(tx: &[u8], block_hash: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + tx.len() + 32);
    // TransactionSource::External = 2
    out.push(2u8);
    out.extend_from_slice(tx);
    if let Some(hash) = block_hash {
        out.extend_from_slice(hash);
    }
    out
}

fn decode_hash32(hash_hex: &str) -> Result<[u8; 32]> {
    let bytes = decode_hex(hash_hex)?;
    if bytes.len() != 32 {
        return Err(anyhow!("block hash length is {} (expected 32)", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Debug)]
enum ValidationResult {
    Valid(TransactionValid),
    Invalid(TransactionInvalid),
    Unknown(TransactionUnknown),
}

#[allow(dead_code)]
#[derive(Debug, Decode)]
struct TransactionValid {
    priority: u64,
    requires: Vec<Vec<u8>>,
    provides: Vec<Vec<u8>>,
    longevity: u64,
    propagate: bool,
}

#[allow(dead_code)]
#[derive(Debug, Decode)]
enum TransactionInvalid {
    Call,
    Payment,
    Future,
    Stale,
    BadProof,
    AncientBirthBlock,
    ExhaustsResources,
    Custom(u8),
    BadMandatory,
    MandatoryDispatch,
}

#[allow(dead_code)]
#[derive(Debug, Decode)]
enum TransactionUnknown {
    CannotLookup,
    NoUnsignedValidator,
    Custom(u8),
}

fn decode_validation_result(bytes: &[u8]) -> Result<ValidationResult> {
    if bytes.first() == Some(&0) {
        let valid = TransactionValid::decode(&mut &bytes[1..])?;
        return Ok(ValidationResult::Valid(valid));
    }

    if bytes.len() >= 2 && bytes[0] == 1 && bytes[1] == 0 {
        let invalid = TransactionInvalid::decode(&mut &bytes[2..])?;
        return Ok(ValidationResult::Invalid(invalid));
    }

    if bytes.len() >= 2 && bytes[0] == 1 && bytes[1] == 1 {
        let unknown = TransactionUnknown::decode(&mut &bytes[2..])?;
        return Ok(ValidationResult::Unknown(unknown));
    }

    Err(anyhow!("unexpected validation response"))
}
