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
const ARCHIVE_WS: &str = "wss://archive.chain.opentensor.ai";
const VALIDATION_METHOD: &str = "TaggedTransactionQueue_validate_transaction";

#[derive(Debug)]
struct Config {
    ws_url: String,
    baseline_priority: u64,
    auto_baseline: bool,
    from_past_block: Option<u64>,
}

impl Config {
    fn from_args() -> Result<Self> {
        let mut ws_url = DEFAULT_WS.to_string();
        let mut ws_overridden = false;
        let mut baseline_priority = 0u64;
        let mut auto_baseline = true;
        let mut from_past_block = None;

        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--ws" => {
                    ws_url = args.next().context("--ws requires a value")?;
                    ws_overridden = true;
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
                "--from-past-block" => {
                    let val = args.next().context("--from-past-block requires a value")?;
                    from_past_block = Some(val.parse().context("invalid --from-past-block")?);
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

        if from_past_block.is_some() && !ws_overridden {
            ws_url = ARCHIVE_WS.to_string();
        }

        Ok(Config {
            ws_url,
            baseline_priority,
            auto_baseline,
            from_past_block,
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
    println!("  --from-past-block <U64>     Scan historical blocks from this height, then continue live");
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
    tipped_staking: AtomicU64,
    evm_tipped_staking: AtomicU64,
    min_priority: AtomicU64,
    max_priority: AtomicU64,
    historical_eta_secs: AtomicU64,
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

    async fn note_tip(&self, tip: u128) {
        if tip == 0 {
            return;
        }
        self.tipped_staking.fetch_add(1, Ordering::Relaxed);
    }

    fn note_evm_tip(&self, tip: u128) {
        if tip == 0 {
            return;
        }
        self.evm_tipped_staking.fetch_add(1, Ordering::Relaxed);
    }

    fn note_priority(&self, priority: u64) {
        let _ = self
            .min_priority
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                Some(cur.min(priority))
            });
        let _ = self
            .max_priority
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                Some(cur.max(priority))
            });
    }

    fn set_historical_eta_secs(&self, secs: Option<u64>) {
        let value = secs.unwrap_or(u64::MAX);
        self.historical_eta_secs.store(value, Ordering::Relaxed);
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
            tipped_staking: AtomicU64::new(0),
            evm_tipped_staking: AtomicU64::new(0),
            min_priority: AtomicU64::new(u64::MAX),
            max_priority: AtomicU64::new(0),
            historical_eta_secs: AtomicU64::new(u64::MAX),
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

    let mut baseline = Baseline::new(config.baseline_priority, config.auto_baseline);
    let mut seen = Seen::new(2048);
    let stats = Arc::new(Stats::default());

    let updater_client = Arc::clone(&client);
    let updater_head_state = Arc::clone(&head_state);
    let updater_stats = Arc::clone(&stats);
    tokio::spawn(async move {
        let mut last_hash = updater_head_state.read().await.hash.clone();
        let mut ticker = interval(Duration::from_secs(6));
        loop {
            ticker.tick().await;
            if let Ok(state) = fetch_head_state(&updater_client).await {
                if state.hash != last_hash {
                    last_hash = state.hash.clone();
                    updater_stats.blocks_scanned.fetch_add(1, Ordering::Relaxed);
                }
                *updater_head_state.write().await = state;
            }
        }
    });

    println!(
        "Connected to {}. Watching pending extrinsics...",
        config.ws_url
    );

    if let Some(start_block) = config.from_past_block {
        scan_past_blocks(
            &client,
            &metadata,
            &head_state,
            &mut baseline,
            &mut seen,
            &stats,
            start_block,
        )
        .await?;
    }


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

#[derive(Deserialize)]
struct BlockResponse {
    block: BlockInner,
}

#[derive(Deserialize)]
struct BlockInner {
    header: HeaderRpc,
    extrinsics: Vec<String>,
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
    process_extrinsic_with_source(
        client,
        metadata,
        head_state,
        baseline,
        seen,
        stats,
        hex,
        TransactionSource::External,
        None,
    )
    .await;
}

async fn scan_past_blocks(
    client: &WsClient,
    metadata: &RuntimeMetadata,
    head_state: &Arc<RwLock<HeadState>>,
    baseline: &mut Baseline,
    seen: &mut Seen,
    stats: &Arc<Stats>,
    start_block: u64,
) -> Result<()> {
    let current = fetch_head_state(client).await?;
    if start_block > current.number {
        return Err(anyhow!(
            "--from-past-block {} is ahead of current block {}",
            start_block,
            current.number
        ));
    }

    let total_blocks = current.number - start_block + 1;
    let started = std::time::Instant::now();
    println!(
        "Scanning blocks {}..={} (historical, {} blocks)...",
        start_block, current.number, total_blocks
    );

    for (idx, number) in (start_block..=current.number).enumerate() {
        let hash: String = client
            .request("chain_getBlockHash", rpc_params![number])
            .await
            .context("chain_getBlockHash failed")?;
        let block: BlockResponse = client
            .request("chain_getBlock", rpc_params![&hash])
            .await
            .context("chain_getBlock failed")?;
        let spec_version = fetch_runtime_spec_version_at(client, &hash).await?;
        let parent_hash = block.block.header.parent_hash.clone();
        let head = HeadState {
            hash,
            number: parse_hex_u64(&block.block.header.number)?,
            spec_version,
        };

        for ext in block.block.extrinsics {
            process_extrinsic_with_head(
                client,
                metadata,
                head_state,
                head.clone(),
                baseline,
                seen,
                stats,
                ext,
                parent_hash.clone(),
            )
            .await;
        }

        let processed = (idx as u64) + 1;
        let remaining = total_blocks.saturating_sub(processed);
        let elapsed = started.elapsed().as_secs_f64();
        let eta = if elapsed > 0.0 && processed > 0 {
            let rate = processed as f64 / elapsed;
            if rate > 0.0 {
                Some((remaining as f64 / rate) as u64)
            } else {
                None
            }
        } else {
            None
        };
        stats.blocks_scanned.store(processed, Ordering::Relaxed);
        stats.set_historical_eta_secs(eta);
    }

    stats.set_historical_eta_secs(None);
    Ok(())
}

async fn process_extrinsic_with_head(
    client: &WsClient,
    metadata: &RuntimeMetadata,
    head_state: &Arc<RwLock<HeadState>>,
    head: HeadState,
    baseline: &mut Baseline,
    seen: &mut Seen,
    stats: &Arc<Stats>,
    hex: String,
    validation_hash: String,
) {
    *head_state.write().await = head.clone();
    process_extrinsic_with_source(
        client,
        metadata,
        head_state,
        baseline,
        seen,
        stats,
        hex,
        TransactionSource::InBlock,
        Some(validation_hash),
    )
    .await;
}

async fn process_extrinsic_with_source(
    client: &WsClient,
    metadata: &RuntimeMetadata,
    head_state: &Arc<RwLock<HeadState>>,
    baseline: &mut Baseline,
    seen: &mut Seen,
    stats: &Arc<Stats>,
    hex: String,
    source: TransactionSource,
    validation_hash: Option<String>,
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
    // Status update per processed tx
    print_status_line_once(stats, head_state).await;

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
    let tip = extract_tip(metadata, &decoded, &decoded.bytes).unwrap_or(0);
    let evm_tip = extract_evm_tip(metadata, &decoded, &decoded.bytes).unwrap_or(0);
    stats.note_tip(tip).await;
    stats.note_evm_tip(evm_tip);

    let validate_hash = validation_hash.as_deref().unwrap_or(&head.hash);
    match validate_transaction(client, validate_hash, &decoded.bytes, source).await {
        Ok(valid) => {
            stats.note_priority(valid.priority);
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
    let min_priority = stats.min_priority.load(Ordering::Relaxed);
    let max_priority = stats.max_priority.load(Ordering::Relaxed);
    let head = { head_state.read().await.clone() };
    let blocks_scanned = stats.blocks_scanned.load(Ordering::Relaxed);
    let eta_secs = stats.historical_eta_secs.load(Ordering::Relaxed);
    let line = if eta_secs != u64::MAX {
        let eta = format_eta(eta_secs);
        format!(
            "\rblock={} spec_version={} blocks_scanned={} eta={} seen={} staking={} tipped={} evm_tipped={} min_priority={} max_priority={} elevated={} errors={}   ",
            head.number,
            head.spec_version,
            blocks_scanned,
            eta,
            total,
            staking,
            tipped,
            evm_tipped,
            if min_priority == u64::MAX { 0 } else { min_priority },
            max_priority,
            elevated,
            errors
        )
    } else {
        format!(
            "\rblock={} spec_version={} blocks_scanned={} seen={} staking={} tipped={} evm_tipped={} min_priority={} max_priority={} elevated={} errors={}   ",
            head.number,
            head.spec_version,
            blocks_scanned,
            total,
            staking,
            tipped,
            evm_tipped,
            if min_priority == u64::MAX { 0 } else { min_priority },
            max_priority,
            elevated,
            errors
        )
    };
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
    #[serde(rename = "parentHash")]
    parent_hash: String,
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

async fn fetch_runtime_spec_version_at(client: &WsClient, hash: &str) -> Result<u32> {
    let version: RuntimeVersionRpc = client
        .request("state_getRuntimeVersion", rpc_params![hash])
        .await
        .context("state_getRuntimeVersion failed")?;
    Ok(version.spec_version)
}

fn parse_hex_u64(value: &str) -> Result<u64> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(trimmed, 16).context("invalid hex number")
}

fn format_eta(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
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
    source: TransactionSource,
) -> Result<TransactionValid> {
    let block_hash = decode_hash32(block_hash_hex)?;
    let params_v3 = encode_validate_params(extrinsic_bytes, Some(&block_hash), source);
    if let Ok(response) = state_call(client, VALIDATION_METHOD, &params_v3, block_hash_hex).await {
        if let Ok(result) = decode_validation_result(&response) {
            return match result {
                ValidationResult::Valid(valid) => Ok(valid),
                ValidationResult::Invalid(err) => Err(anyhow!("transaction invalid: {err:?}")),
                ValidationResult::Unknown(err) => Err(anyhow!("transaction unknown: {err:?}")),
            };
        }
    }

    let params_v2 = encode_validate_params(extrinsic_bytes, None, source);
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

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum TransactionSource {
    InBlock,
    Local,
    External,
}

fn encode_validate_params(
    tx: &[u8],
    block_hash: Option<&[u8; 32]>,
    source: TransactionSource,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + tx.len() + 32);
    let source_byte = match source {
        TransactionSource::InBlock => 0,
        TransactionSource::Local => 1,
        TransactionSource::External => 2,
    };
    out.push(source_byte);
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
