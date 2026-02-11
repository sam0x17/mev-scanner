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
use scale_value::scale;
use scale_value::{Composite, Value, ValueDef};
use serde::Deserialize;
use sp_crypto_hashing::blake2_256;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashEntry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use subxt::config::SubstrateConfig;
use subxt::events::Events;
use subxt::backend::BackendExt;
use subxt::utils::{AccountId32, H256, MultiAddress};
use subxt::OnlineClient;
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
    inspect_account: Option<String>,
    inspect_blocks: u64,
    calculate_transaction_fees: bool,
}

impl Config {
    fn from_args() -> Result<Self> {
        let mut ws_url = DEFAULT_WS.to_string();
        let mut ws_overridden = false;
        let mut baseline_priority = 0u64;
        let mut auto_baseline = true;
        let mut from_past_block = None;
        let mut inspect_account = None;
        let mut inspect_blocks = 200u64;
        let mut calculate_transaction_fees = false;

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
                "--inspect-account" => {
                    let val = args.next().context("--inspect-account requires a value")?;
                    inspect_account = Some(val);
                }
                "--inspect-blocks" => {
                    let val = args.next().context("--inspect-blocks requires a value")?;
                    inspect_blocks = val.parse().context("invalid --inspect-blocks")?;
                }
                "--calculate-transaction-fees" => {
                    calculate_transaction_fees = true;
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

        if (from_past_block.is_some() || calculate_transaction_fees) && !ws_overridden {
            ws_url = ARCHIVE_WS.to_string();
        }

        Ok(Config {
            ws_url,
            baseline_priority,
            auto_baseline,
            from_past_block,
            inspect_account,
            inspect_blocks,
            calculate_transaction_fees,
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
    println!("  --inspect-account <SS58>    Inspect recent blocks for transactions involving this account");
    println!("  --inspect-blocks <U64>      Blocks to scan for --inspect-account (default: 200)");
    println!("  --calculate-transaction-fees  Sum TransactionPayment fees for the past year and exit");
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
    replacements_detected: AtomicU64,
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

    fn inc_replacement(&self) {
        self.replacements_detected.fetch_add(1, Ordering::Relaxed);
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

#[derive(Clone, Debug)]
struct ReplacementEntry {
    hash: String,
    first_seen: u64,
}

#[derive(Default)]
struct ReplacementTracker {
    by_signer_nonce: DashMap<([u8; 32], u64), ReplacementEntry>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            total_seen: AtomicU64::new(0),
            staking_seen: AtomicU64::new(0),
            elevated_found: AtomicU64::new(0),
            validation_errors: AtomicU64::new(0),
            replacements_detected: AtomicU64::new(0),
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

    if config.calculate_transaction_fees {
        if config.inspect_account.is_some() {
            return Err(anyhow!(
                "--calculate-transaction-fees cannot be combined with --inspect-account"
            ));
        }
        calculate_transaction_fees(&config.ws_url).await?;
        return Ok(());
    }

    if let Some(account) = config.inspect_account.as_deref() {
        inspect_account(&config.ws_url, account, config.inspect_blocks).await?;
        return Ok(());
    }

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
    let replacements = Arc::new(ReplacementTracker::default());

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
            &replacements,
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
                    &replacements,
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
                    &replacements,
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
    replacements: &Arc<ReplacementTracker>,
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
                replacements,
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
    replacements: &Arc<ReplacementTracker>,
    hex: String,
) {
    process_extrinsic_with_source(
        client,
        metadata,
        head_state,
        baseline,
        seen,
        stats,
        replacements,
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
    replacements: &Arc<ReplacementTracker>,
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
                replacements,
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
    replacements: &Arc<ReplacementTracker>,
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
        replacements,
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
    replacements: &Arc<ReplacementTracker>,
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

    if let Some((signer, nonce)) = extract_signer_and_nonce(metadata, &decoded, &decoded.bytes) {
        let key = (signer, nonce);
        let entry = replacements.by_signer_nonce.entry(key);
        match entry {
            DashEntry::Vacant(vacant) => {
                vacant.insert(ReplacementEntry {
                    hash: hash_hex.clone(),
                    first_seen: now_unix(),
                });
            }
            DashEntry::Occupied(mut occupied) => {
                let current = occupied.get();
                if current.hash != hash_hex {
                    stats.inc_replacement();
                    let signer_str = AccountId32(signer).to_string();
                    let ts = now_unix();
                    let head = { head_state.read().await.clone() };
                    println!(
                        "[{ts}] replacement_detected signer={signer_str} nonce={nonce} old_tx={} new_tx={} block={} spec_version={}",
                        current.hash,
                        hash_hex,
                        head.number,
                        head.spec_version
                    );
                    occupied.insert(ReplacementEntry {
                        hash: hash_hex.clone(),
                        first_seen: current.first_seen,
                    });
                }
            }
        }
    }

    // Track EVM tips for all transactions once decoded.
    let evm_tip = extract_evm_tip(metadata, &decoded, &decoded.bytes).unwrap_or(0);
    stats.note_evm_tip(evm_tip);

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
    stats.note_tip(tip).await;

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
    let replacements = stats.replacements_detected.load(Ordering::Relaxed);
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
            "\rblock={} spec_version={} blocks_scanned={} eta={} seen={} staking={} tipped={} evm_tipped={} min_priority={} max_priority={} elevated={} replacements={} errors={}   ",
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
            replacements,
            errors
        )
    } else {
        format!(
            "\rblock={} spec_version={} blocks_scanned={} seen={} staking={} tipped={} evm_tipped={} min_priority={} max_priority={} elevated={} replacements={} errors={}   ",
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
            replacements,
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

async fn inspect_account(ws_url: &str, account: &str, blocks_back: u64) -> Result<()> {
    let target = AccountId32::from_str(account).context("invalid SS58 account")?;
    let target_bytes = target.0;
    let client = OnlineClient::<SubstrateConfig>::from_url(ws_url)
        .await
        .context("failed to connect via subxt")?;

    let latest = client.blocks().at_latest().await?;
    let latest_number = latest.header().number;
    let mut hashes = Vec::new();
    let mut current_hash = latest.hash();

    let mut remaining = blocks_back.max(1);
    while remaining > 0 {
        let block = client.blocks().at(current_hash).await?;
        let header = block.header();
        hashes.push((header.number, current_hash));
        if header.number == 0 {
            break;
        }
        current_hash = header.parent_hash;
        remaining -= 1;
    }

    hashes.sort_by_key(|(number, _)| *number);
    let start = hashes.first().map(|(n, _)| *n).unwrap_or(latest_number);
    let end = hashes.last().map(|(n, _)| *n).unwrap_or(latest_number);
    println!(
        "Inspecting account {} in blocks {}..={} ({} blocks) via {}",
        target,
        start,
        end,
        hashes.len(),
        ws_url
    );

    let mut match_count = 0u64;
    for (number, hash) in hashes {
        let block = client.blocks().at(hash).await?;
        let extrinsics = block.extrinsics().await?;
        for ext in extrinsics.iter() {
            if !ext.is_signed() {
                continue;
            }

            let signer = ext.address_bytes().and_then(decode_subxt_address);
            let mut matched = false;
            let mut reasons: Vec<String> = Vec::new();

            if signer.as_ref() == Some(&target) {
                matched = true;
                reasons.push("signer".to_string());
            }

            let mut field_matches = Vec::new();
            let mut nested_call = None;
            if let Ok(fields) = ext.field_values() {
                collect_account_matches_in_composite(
                    &fields,
                    &target_bytes,
                    &mut Vec::new(),
                    &mut field_matches,
                );
                nested_call = extract_call_path_from_fields(&fields);
            }

            if !field_matches.is_empty() {
                matched = true;
                reasons.push(format!("fields={}", field_matches.join(",")));
            }

            if matched {
                match_count += 1;
                let pallet = ext.pallet_name().unwrap_or("-");
                let call = ext.variant_name().unwrap_or("-");
                let hash_hex = format!("0x{}", hex::encode(ext.hash()));
                let signer_str = signer
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "-".to_string());
                let nested_call = nested_call.unwrap_or_else(|| "-".to_string());

                println!(
                    "block={} index={} hash={} signer={} call={}::{} nested_call={} reasons={}",
                    number,
                    ext.index(),
                    hash_hex,
                    signer_str,
                    pallet,
                    call,
                    nested_call,
                    reasons.join(";")
                );
            }
        }
    }

    println!("Found {} matching extrinsics.", match_count);
    Ok(())
}

async fn calculate_transaction_fees(ws_url: &str) -> Result<()> {
    println!("Calculating total transaction fees for the past year...");

    let rpc_client = WsClientBuilder::default()
        .build(ws_url)
        .await
        .context("failed to connect to ws endpoint for rpc")?;
    let api = OnlineClient::<SubstrateConfig>::from_url(ws_url)
        .await
        .context("failed to connect via subxt")?;

    let (latest_number, latest_hash) = fetch_latest_block_number_and_hash(&rpc_client).await?;
    let latest_metadata = fetch_metadata_at(&api, latest_hash).await?;
    let timestamp_key =
        resolve_timestamp_storage_key(&latest_metadata).unwrap_or_else(timestamp_storage_key);

    let year_ms = 365u128 * 24 * 60 * 60 * 1000;

    println!("Using endpoint: {}", ws_url);

    let start_block = match fetch_block_timestamp_raw_rpc(
        &rpc_client,
        &timestamp_key,
        &latest_hash,
    )
    .await
    {
        Ok(latest_ts_raw) => {
            let timestamp_in_seconds = latest_ts_raw < 1_000_000_000_000u128;
            let latest_ts_ms = if timestamp_in_seconds {
                latest_ts_raw * 1000
            } else {
                latest_ts_raw
            };
            let start_ts_ms = latest_ts_ms.saturating_sub(year_ms);
            println!(
                "Latest block: {} timestamp_ms={}{}",
                latest_number,
                latest_ts_ms,
                if timestamp_in_seconds {
                    " (converted from seconds)"
                } else {
                    ""
                }
            );
            println!("Target start timestamp_ms={}", start_ts_ms);
            match find_block_number_at_or_after_timestamp(
                &rpc_client,
                &timestamp_key,
                start_ts_ms,
                latest_number,
                timestamp_in_seconds,
            )
            .await
            {
                Ok(block) => block,
                Err(err) => {
                    let (block_time_ms, source) =
                        resolve_block_time_ms(&latest_metadata).unwrap_or((12_000, "default"));
                    let blocks_per_year = year_ms / block_time_ms.max(1);
                    let start = latest_number.saturating_sub(blocks_per_year as u64);
                    println!(
                        "Timestamp search failed: {}. Falling back to estimate.",
                        err
                    );
                    println!(
                        "Estimated block_time_ms={} source={}",
                        block_time_ms, source
                    );
                    start
                }
            }
        }
        Err(err) => {
            let (block_time_ms, source) =
                resolve_block_time_ms(&latest_metadata).unwrap_or((12_000, "default"));
            let blocks_per_year = year_ms / block_time_ms.max(1);
            let start = latest_number.saturating_sub(blocks_per_year as u64);
            println!(
                "Latest block: {} (timestamp unavailable: {})",
                latest_number, err
            );
            println!(
                "Falling back to block-time estimate: block_time_ms={} source={}",
                block_time_ms, source
            );
            start
        }
    };

    let total_blocks = latest_number.saturating_sub(start_block) + 1;
    println!(
        "Scanning blocks {}..={} ({} blocks)",
        start_block, latest_number, total_blocks
    );

    let events_key = system_events_storage_key();
    let start_hash = fetch_block_hash_h256(&rpc_client, start_block).await?;
    let mut current_metadata = fetch_metadata_at(&api, start_hash).await?;

    let started = Instant::now();
    let mut total_fee: u128 = 0;
    let mut fee_events: u64 = 0;
    let mut fee_misses: u64 = 0;
    let mut blocks_processed: u64 = 0;

    for number in start_block..=latest_number {
        let hash = fetch_block_hash_h256(&rpc_client, number).await?;
        let event_bytes = fetch_events_bytes(&api, &events_key, hash).await?;
        let Some(event_bytes) = event_bytes else {
            fee_misses = fee_misses.saturating_add(1);
            blocks_processed += 1;
            continue;
        };

        let mut result = sum_fees_from_events(&Events::<SubstrateConfig>::decode_from(
            event_bytes.clone(),
            current_metadata.clone(),
        ));
        if result.had_decode_error {
            let refreshed = fetch_metadata_at(&api, hash).await?;
            current_metadata = refreshed;
            result = sum_fees_from_events(&Events::<SubstrateConfig>::decode_from(
                event_bytes,
                current_metadata.clone(),
            ));
        }

        total_fee = total_fee.saturating_add(result.total_fee);
        fee_events = fee_events.saturating_add(result.fee_events);
        fee_misses = fee_misses.saturating_add(result.fee_misses);
        blocks_processed += 1;

        if blocks_processed % 250 == 0 || number == latest_number {
            let elapsed = started.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                blocks_processed as f64 / elapsed
            } else {
                0.0
            };
            let remaining = latest_number.saturating_sub(number);
            let eta = if rate > 0.0 {
                (remaining as f64 / rate) as u64
            } else {
                0
            };
            let line = format!(
                "\rblock={} processed={} fee_events={} fee_misses={} total_fee={} eta={}   ",
                number,
                blocks_processed,
                fee_events,
                fee_misses,
                total_fee,
                format_eta(eta)
            );
            let _ = std::io::stdout().write_all(line.as_bytes());
            let _ = std::io::stdout().flush();
        }
    }

    println!(
        "\nTotal transaction fees (raw units): {}",
        total_fee
    );
    if fee_misses > 0 {
        println!(
            "Warning: {} fee events could not be decoded; total may be understated.",
            fee_misses
        );
    }

    Ok(())
}

async fn fetch_block_hash_h256(client: &WsClient, number: u64) -> Result<H256> {
    let hash: Option<String> = client
        .request("chain_getBlockHash", rpc_params![number])
        .await
        .context("chain_getBlockHash failed")?;
    let hash = hash.context("block hash not found")?;
    decode_hash256(&hash)
}

fn decode_hash256(hash_hex: &str) -> Result<H256> {
    let bytes = decode_hex(hash_hex)?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "block hash length is {} (expected 32)",
            bytes.len()
        ));
    }
    Ok(H256::from_slice(&bytes))
}

fn system_events_storage_key() -> Vec<u8> {
    storage_key_from_prefix_entry("System", "Events")
}

fn timestamp_storage_key() -> Vec<u8> {
    storage_key_from_prefix_entry("Timestamp", "Now")
}

fn storage_key_from_prefix_entry(prefix: &str, entry: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&sp_crypto_hashing::twox_128(prefix.as_bytes()));
    key.extend_from_slice(&sp_crypto_hashing::twox_128(entry.as_bytes()));
    key
}

fn resolve_timestamp_storage_key(
    metadata: &subxt::metadata::Metadata,
) -> Option<Vec<u8>> {
    let mut fallback: Option<Vec<u8>> = None;
    for pallet in metadata.pallets() {
        let Some(storage) = pallet.storage() else { continue };
        let prefix = storage.prefix();
        for entry in storage.entries() {
            if !entry.name().eq_ignore_ascii_case("Now") {
                continue;
            }
            let key = storage_key_from_prefix_entry(prefix, entry.name());
            let pallet_name = pallet.name().to_ascii_lowercase();
            let prefix_name = prefix.to_ascii_lowercase();
            if pallet_name.contains("timestamp") || prefix_name.contains("timestamp") {
                return Some(key);
            }
            fallback = Some(key);
        }
    }
    fallback
}

fn resolve_block_time_ms(metadata: &subxt::metadata::Metadata) -> Option<(u128, &'static str)> {
    for pallet in metadata.pallets() {
        let name = pallet.name().to_ascii_lowercase();
        if !name.contains("timestamp") {
            continue;
        }
        if let Some(constant) = pallet.constant_by_name("MinimumPeriod") {
            if let Some(value) = decode_constant_u128(metadata, constant) {
                return Some((value.saturating_mul(2), "Timestamp::MinimumPeriod"));
            }
        }
    }

    for pallet in metadata.pallets() {
        let name = pallet.name().to_ascii_lowercase();
        if name == "babe" {
            if let Some(constant) = pallet.constant_by_name("ExpectedBlockTime") {
                if let Some(value) = decode_constant_u128(metadata, constant) {
                    return Some((value, "Babe::ExpectedBlockTime"));
                }
            }
        }
    }

    for pallet in metadata.pallets() {
        let name = pallet.name().to_ascii_lowercase();
        if name == "aura" {
            if let Some(constant) = pallet.constant_by_name("SlotDuration") {
                if let Some(value) = decode_constant_u128(metadata, constant) {
                    return Some((value, "Aura::SlotDuration"));
                }
            }
        }
    }

    None
}

fn decode_constant_u128(
    metadata: &subxt::metadata::Metadata,
    constant: &subxt::metadata::types::ConstantMetadata,
) -> Option<u128> {
    let value = scale::decode_as_type(
        &mut &*constant.value(),
        constant.ty(),
        metadata.types(),
    )
    .ok()?;
    extract_u128(&value)
}

fn format_hash_hex(hash: &H256) -> String {
    format!("0x{}", hex::encode(hash.as_bytes()))
}

async fn fetch_storage_bytes(
    client: &WsClient,
    key: &[u8],
    hash: &H256,
) -> Result<Option<Vec<u8>>> {
    let key_hex = format!("0x{}", hex::encode(key));
    let hash_hex = format_hash_hex(hash);
    let response: Option<String> = client
        .request("state_getStorage", rpc_params![key_hex, hash_hex])
        .await
        .context("state_getStorage failed")?;
    match response {
        Some(hex) => Ok(Some(decode_hex(&hex)?)),
        None => Ok(None),
    }
}

fn decode_scale_moment(bytes: &[u8]) -> Result<u128> {
    match bytes.len() {
        8 => {
            let mut cursor = &bytes[..];
            let value = u64::decode(&mut cursor)?;
            if !cursor.is_empty() {
                return Err(anyhow!("timestamp decode left trailing bytes"));
            }
            Ok(value as u128)
        }
        16 => {
            let mut cursor = &bytes[..];
            let value = u128::decode(&mut cursor)?;
            if !cursor.is_empty() {
                return Err(anyhow!("timestamp decode left trailing bytes"));
            }
            Ok(value)
        }
        other => Err(anyhow!("unexpected timestamp byte length: {}", other)),
    }
}

async fn fetch_block_timestamp_raw_rpc(
    client: &WsClient,
    key: &[u8],
    hash: &H256,
) -> Result<u128> {
    if let Some(bytes) = fetch_storage_bytes(client, key, hash).await? {
        return decode_scale_moment(&bytes).context("failed to decode timestamp bytes");
    }

    let hash_hex = format_hash_hex(hash);
    let metadata = fetch_runtime_metadata_at(client, Some(&hash_hex)).await?;
    fetch_block_timestamp_from_extrinsics(client, &hash_hex, &metadata).await
}

async fn fetch_block_timestamp_millis_rpc(
    client: &WsClient,
    key: &[u8],
    hash: &H256,
    timestamp_in_seconds: bool,
) -> Result<u128> {
    let raw = fetch_block_timestamp_raw_rpc(client, key, hash).await?;
    Ok(if timestamp_in_seconds { raw * 1000 } else { raw })
}

async fn fetch_metadata_at(
    api: &OnlineClient<SubstrateConfig>,
    hash: H256,
) -> Result<subxt::metadata::Metadata> {
    const METADATA_VERSIONS: [u32; 3] = [16, 15, 14];
    let backend = api.backend();
    for version in METADATA_VERSIONS {
        if let Ok(metadata) = backend.metadata_at_version(version, hash).await {
            return Ok(metadata);
        }
    }
    backend.legacy_metadata(hash).await.map_err(Into::into)
}

async fn fetch_events_bytes(
    api: &OnlineClient<SubstrateConfig>,
    key: &[u8],
    hash: H256,
) -> Result<Option<Vec<u8>>> {
    let backend = api.backend();
    backend
        .storage_fetch_value(key.to_vec(), hash)
        .await
        .map_err(Into::into)
}

async fn fetch_latest_block_number_and_hash(client: &WsClient) -> Result<(u64, H256)> {
    let hash_hex: String = match client
        .request("chain_getFinalizedHead", rpc_params![])
        .await
    {
        Ok(hash) => hash,
        Err(_) => client
            .request("chain_getBlockHash", rpc_params![])
            .await
            .context("chain_getBlockHash failed")?,
    };
    let header: HeaderRpc = client
        .request("chain_getHeader", rpc_params![&hash_hex])
        .await
        .context("chain_getHeader failed")?;
    let number = parse_hex_u64(&header.number)?;
    let hash = decode_hash256(&hash_hex)?;
    Ok((number, hash))
}

async fn fetch_runtime_metadata_at(
    client: &WsClient,
    hash_hex: Option<&str>,
) -> Result<RuntimeMetadata> {
    let attempt: Result<String, _> = match hash_hex {
        Some(hash) => client.request("state_getMetadata", rpc_params![hash]).await,
        None => client.request("state_getMetadata", rpc_params![]).await,
    };
    match attempt {
        Ok(metadata_hex) => decode_runtime_metadata_hex(&metadata_hex),
        Err(err) => {
            if hash_hex.is_some() {
                let fallback: String = client
                    .request("state_getMetadata", rpc_params![])
                    .await
                    .context("state_getMetadata failed")?;
                return decode_runtime_metadata_hex(&fallback);
            }
            Err(anyhow!(err))
        }
    }
}

fn decode_runtime_metadata_hex(metadata_hex: &str) -> Result<RuntimeMetadata> {
    let metadata_bytes = decode_hex(metadata_hex).context("metadata hex decode failed")?;
    if let Ok(prefixed) = RuntimeMetadataPrefixed::decode(&mut &metadata_bytes[..]) {
        if prefixed.0 == META_RESERVED {
            return Ok(prefixed.1);
        }
    }
    Ok(RuntimeMetadata::decode(&mut &metadata_bytes[..])?)
}

async fn fetch_block_timestamp_from_extrinsics(
    client: &WsClient,
    hash_hex: &str,
    metadata: &RuntimeMetadata,
) -> Result<u128> {
    let block: BlockResponse = client
        .request("chain_getBlock", rpc_params![hash_hex])
        .await
        .context("chain_getBlock failed")?;
    let mut fallback_large: Option<u128> = None;
    let mut raw_fallback: Option<u128> = None;
    for ext in block.block.extrinsics {
        let raw = match decode_hex(&ext) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let decoded = match decode_extrinsic(metadata, &raw) {
            Ok(ext) => ext,
            Err(_) => continue,
        };
        let pallet = decoded.ext.pallet_name().to_ascii_lowercase();
        let call = decoded.ext.call_name().to_ascii_lowercase();
        let is_timestamp_pallet = pallet.contains("timestamp");

        if is_timestamp_pallet {
            if let Some(moment) =
                extract_call_u128(metadata, &decoded, &["now", "moment", "time"])
            {
                return Ok(moment);
            }
        }

        if decoded.ext.is_signed() {
            continue;
        }

        if call.contains("timestamp") || call.contains("set") {
            if let Some(moment) =
                extract_call_u128(metadata, &decoded, &["now", "moment", "time"])
            {
                if moment >= 1_000_000_000 {
                    return Ok(moment);
                }
                if fallback_large.is_none() {
                    fallback_large = Some(moment);
                }
            }
        }

        if raw_fallback.is_none() {
            if let Some(moment) = extract_moment_from_raw_extrinsic(&raw) {
                if moment >= 1_000_000_000 {
                    raw_fallback = Some(moment);
                }
            }
        }
    }

    if let Some(moment) = fallback_large {
        return Ok(moment);
    }
    if let Some(moment) = raw_fallback {
        return Ok(moment);
    }

    Err(anyhow!("timestamp extrinsic not found"))
}

fn extract_call_u128(
    metadata: &RuntimeMetadata,
    decoded: &DecodedExtrinsic,
    preferred_names: &[&str],
) -> Option<u128> {
    let mut fallback = None;
    for arg in decoded.ext.call_data() {
        let range = arg.range();
        if range.end > decoded.bytes.len() {
            continue;
        }
        let arg_bytes = &decoded.bytes[range];
        let value = decode_value(metadata, *arg.ty(), arg_bytes).ok()?;
        if let Some(n) = extract_u128(&value) {
            if preferred_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(arg.name()))
            {
                return Some(n);
            }
            if fallback.is_none() {
                fallback = Some(n);
            }
        }
    }
    fallback
}

fn extract_moment_from_raw_extrinsic(raw: &[u8]) -> Option<u128> {
    let bytes = strip_extrinsic_len_prefix(raw);
    if bytes.len() < 3 {
        return None;
    }
    let version = bytes[0];
    let is_signed = (version & 0b1000_0000) != 0;
    if is_signed {
        return None;
    }
    let args = &bytes[3..];
    if let Some(val) = decode_u128_or_u64(args) {
        return Some(val);
    }
    None
}

fn strip_extrinsic_len_prefix(raw: &[u8]) -> &[u8] {
    let mut cursor = raw;
    if let Ok(Compact(len)) = Compact::<u32>::decode(&mut cursor) {
        if len as usize == cursor.len() {
            return cursor;
        }
    }
    raw
}

fn decode_u128_or_u64(bytes: &[u8]) -> Option<u128> {
    if bytes.len() >= 16 {
        let mut cursor = &bytes[..];
        if let Ok(val) = u128::decode(&mut cursor) {
            return Some(val);
        }
    }
    if bytes.len() >= 8 {
        let mut cursor = &bytes[..];
        if let Ok(val) = u64::decode(&mut cursor) {
            return Some(val as u128);
        }
    }
    None
}

async fn find_block_number_at_or_after_timestamp(
    rpc_client: &WsClient,
    timestamp_key: &[u8],
    target_ts_ms: u128,
    latest_number: u64,
    timestamp_in_seconds: bool,
) -> Result<u64> {
    let genesis_hash = fetch_block_hash_h256(rpc_client, 0).await?;
    let genesis_ts = fetch_block_timestamp_millis_rpc(
        rpc_client,
        timestamp_key,
        &genesis_hash,
        timestamp_in_seconds,
    )
    .await?;
    if genesis_ts >= target_ts_ms {
        return Ok(0);
    }

    let latest_hash = fetch_block_hash_h256(rpc_client, latest_number).await?;
    let latest_ts = fetch_block_timestamp_millis_rpc(
        rpc_client,
        timestamp_key,
        &latest_hash,
        timestamp_in_seconds,
    )
    .await?;
    if latest_ts < target_ts_ms {
        return Ok(latest_number);
    }

    let mut low = 0u64;
    let mut high = latest_number;
    let mut best = latest_number;

    while low <= high {
        let mid = low + (high - low) / 2;
        let hash = fetch_block_hash_h256(rpc_client, mid).await?;
        let ts = fetch_block_timestamp_millis_rpc(
            rpc_client,
            timestamp_key,
            &hash,
            timestamp_in_seconds,
        )
        .await?;
        if ts >= target_ts_ms {
            best = mid;
            if mid == 0 {
                break;
            }
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }

    Ok(best)
}

struct FeeSum {
    total_fee: u128,
    fee_events: u64,
    fee_misses: u64,
    had_decode_error: bool,
}

fn sum_fees_from_events(events: &Events<SubstrateConfig>) -> FeeSum {
    let mut total = 0u128;
    let mut fee_events = 0u64;
    let mut fee_misses = 0u64;
    let mut had_decode_error = false;

    for event in events.iter() {
        let event = match event {
            Ok(ev) => ev,
            Err(_) => {
                had_decode_error = true;
                fee_misses += 1;
                continue;
            }
        };

        if !event.pallet_name().eq_ignore_ascii_case("TransactionPayment") {
            continue;
        }
        let variant = event.variant_name();
        if !variant.eq_ignore_ascii_case("TransactionFeePaid")
            && !variant.to_ascii_lowercase().contains("feepaid")
        {
            continue;
        }

        fee_events += 1;
        let fields = match event.field_values() {
            Ok(fields) => fields,
            Err(_) => {
                fee_misses += 1;
                continue;
            }
        };
        if let Some(fee) = extract_fee_from_transaction_payment_fields(&fields) {
            total = total.saturating_add(fee);
        } else {
            fee_misses += 1;
        }
    }

    FeeSum {
        total_fee: total,
        fee_events,
        fee_misses,
        had_decode_error,
    }
}

fn extract_fee_from_transaction_payment_fields<C>(fields: &Composite<C>) -> Option<u128> {
    match fields {
        Composite::Named(entries) => {
            let mut fee: Option<u128> = None;
            let mut tip: Option<u128> = None;
            for (name, value) in entries {
                if name.eq_ignore_ascii_case("actual_fee")
                    || name.eq_ignore_ascii_case("actualFee")
                {
                    return extract_u128(value);
                }
                if name.eq_ignore_ascii_case("fee")
                    || name.eq_ignore_ascii_case("amount")
                    || name.eq_ignore_ascii_case("partial_fee")
                {
                    fee = fee.or_else(|| extract_u128(value));
                }
                if name.eq_ignore_ascii_case("tip") {
                    tip = tip.or_else(|| extract_u128(value));
                }
            }
            if let Some(fee) = fee {
                return Some(fee.saturating_add(tip.unwrap_or(0)));
            }
            None
        }
        Composite::Unnamed(values) => {
            if values.len() < 2 {
                return None;
            }
            let fee = extract_u128(&values[1])?;
            let tip = if values.len() >= 3 {
                extract_u128(&values[2]).unwrap_or(0)
            } else {
                0
            };
            Some(fee.saturating_add(tip))
        }
    }
}

fn decode_subxt_address(bytes: &[u8]) -> Option<AccountId32> {
    let mut cursor = bytes;
    let address = MultiAddress::<AccountId32, u32>::decode(&mut cursor).ok()?;
    match address {
        MultiAddress::Id(id) => Some(id),
        _ => None,
    }
}

fn extract_call_path_from_fields<C>(composite: &Composite<C>) -> Option<String> {
    match composite {
        Composite::Named(fields) => {
            for (name, value) in fields {
                if name == "call" {
                    if let Some(path) = extract_call_path_from_value(value) {
                        return Some(path);
                    }
                }
            }
            for (_, value) in fields {
                if let Some(path) = extract_call_path_from_value(value) {
                    return Some(path);
                }
            }
            None
        }
        Composite::Unnamed(values) => {
            for value in values {
                if let Some(path) = extract_call_path_from_value(value) {
                    return Some(path);
                }
            }
            None
        }
    }
}

fn extract_call_path_from_value<C>(value: &Value<C>) -> Option<String> {
    match &value.value {
        ValueDef::Variant(variant) => {
            let name = variant.name.clone();
            if let Some(inner) = first_variant_in_composite(&variant.values) {
                Some(format!("{name}::{inner}"))
            } else {
                Some(name)
            }
        }
        ValueDef::Composite(composite) => first_variant_in_composite(composite),
        _ => None,
    }
}

fn first_variant_in_composite<C>(composite: &Composite<C>) -> Option<String> {
    match composite {
        Composite::Named(fields) => {
            for (_, value) in fields {
                if let Some(path) = extract_call_path_from_value(value) {
                    return Some(path);
                }
            }
            None
        }
        Composite::Unnamed(values) => {
            for value in values {
                if let Some(path) = extract_call_path_from_value(value) {
                    return Some(path);
                }
            }
            None
        }
    }
}

fn collect_account_matches_in_composite<C>(
    composite: &Composite<C>,
    target: &[u8; 32],
    path: &mut Vec<String>,
    matches: &mut Vec<String>,
) {
    if let Some(bytes) = composite_as_u8_32(composite) {
        if &bytes == target {
            push_account_match(path, matches);
        }
    }

    match composite {
        Composite::Named(fields) => {
            for (name, value) in fields {
                path.push(name.clone());
                collect_account_matches_in_value(value, target, path, matches);
                path.pop();
            }
        }
        Composite::Unnamed(values) => {
            for (idx, value) in values.iter().enumerate() {
                path.push(format!("#{idx}"));
                collect_account_matches_in_value(value, target, path, matches);
                path.pop();
            }
        }
    }
}

fn collect_account_matches_in_value<C>(
    value: &Value<C>,
    target: &[u8; 32],
    path: &mut Vec<String>,
    matches: &mut Vec<String>,
) {
    match &value.value {
        ValueDef::Variant(variant) => {
            path.push(variant.name.clone());
            collect_account_matches_in_composite(&variant.values, target, path, matches);
            path.pop();
        }
        ValueDef::Composite(composite) => {
            collect_account_matches_in_composite(composite, target, path, matches);
        }
        ValueDef::Primitive(scale_value::Primitive::U256(bytes))
        | ValueDef::Primitive(scale_value::Primitive::I256(bytes)) => {
            if bytes.as_slice() == target {
                push_account_match(path, matches);
            }
        }
        ValueDef::Primitive(scale_value::Primitive::String(value)) => {
            if let Ok(account) = AccountId32::from_str(value) {
                if account.0 == *target {
                    push_account_match(path, matches);
                }
            }
        }
        _ => {}
    }
}

fn composite_as_u8_32<C>(composite: &Composite<C>) -> Option<[u8; 32]> {
    match composite {
        Composite::Unnamed(values) => u8_array_from_values(values),
        Composite::Named(fields) => {
            if fields.len() != 32 {
                return None;
            }
            let mut out = [0u8; 32];
            for (idx, (_, value)) in fields.iter().enumerate() {
                out[idx] = value_as_u8(value)?;
            }
            Some(out)
        }
    }
}

fn u8_array_from_values<C>(values: &[Value<C>]) -> Option<[u8; 32]> {
    if values.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    for (idx, value) in values.iter().enumerate() {
        out[idx] = value_as_u8(value)?;
    }
    Some(out)
}

fn value_as_u8<C>(value: &Value<C>) -> Option<u8> {
    match &value.value {
        ValueDef::Primitive(scale_value::Primitive::U128(byte)) => {
            if *byte > u8::MAX as u128 {
                None
            } else {
                Some(*byte as u8)
            }
        }
        _ => None,
    }
}

fn push_account_match(path: &[String], matches: &mut Vec<String>) {
    if path.is_empty() {
        matches.push("<root>".to_string());
    } else {
        matches.push(path.join("."));
    }
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

fn extract_signer_and_nonce(
    metadata: &RuntimeMetadata,
    decoded: &DecodedExtrinsic,
    bytes: &[u8],
) -> Option<([u8; 32], u64)> {
    let signer = extract_signer(metadata, decoded, bytes)?;
    let nonce = extract_nonce(metadata, decoded, bytes)?;
    Some((signer, nonce))
}

fn extract_signer(
    metadata: &RuntimeMetadata,
    decoded: &DecodedExtrinsic,
    bytes: &[u8],
) -> Option<[u8; 32]> {
    let sig = decoded.ext.signature_payload()?;
    let range = sig.address_range();
    if range.end > bytes.len() {
        return None;
    }
    let addr_bytes = &bytes[range];
    let value = decode_value(metadata, *sig.address_type(), addr_bytes).ok()?;
    find_account_id_in_value(&value)
}

fn extract_nonce(
    metadata: &RuntimeMetadata,
    decoded: &DecodedExtrinsic,
    bytes: &[u8],
) -> Option<u64> {
    let exts = decoded.ext.transaction_extension_payload()?;
    for ext in exts.iter() {
        let range = ext.range();
        if range.end > bytes.len() {
            continue;
        }
        let ext_bytes = &bytes[range];
        let value = decode_value(metadata, *ext.ty(), ext_bytes).ok()?;
        if let Some(nonce) = find_nonce_in_value(&value) {
            return Some(nonce);
        }
    }
    None
}

fn find_nonce_in_value<C>(value: &Value<C>) -> Option<u64> {
    match &value.value {
        ValueDef::Composite(composite) => find_nonce_in_composite(composite),
        ValueDef::Variant(variant) => find_nonce_in_composite(&variant.values),
        _ => None,
    }
}

fn find_nonce_in_composite<C>(composite: &Composite<C>) -> Option<u64> {
    match composite {
        Composite::Named(fields) => {
            for (name, val) in fields {
                if name.eq_ignore_ascii_case("nonce") || name.eq_ignore_ascii_case("index") {
                    if let Some(n) = extract_u128(val) {
                        if n <= u64::MAX as u128 {
                            return Some(n as u64);
                        }
                    }
                }
                if let Some(nonce) = find_nonce_in_value(val) {
                    return Some(nonce);
                }
            }
        }
        Composite::Unnamed(values) => {
            for val in values {
                if let Some(nonce) = find_nonce_in_value(val) {
                    return Some(nonce);
                }
            }
        }
    }
    None
}

fn find_account_id_in_value(value: &Value<()>) -> Option<[u8; 32]> {
    find_account_id_in_value_any(value)
}

fn find_account_id_in_value_any<C>(value: &Value<C>) -> Option<[u8; 32]> {
    match &value.value {
        ValueDef::Variant(variant) => {
            if variant.name.eq_ignore_ascii_case("id") || variant.name.eq_ignore_ascii_case("accountid32") {
                if let Some(bytes) = find_account_id_in_composite(&variant.values) {
                    return Some(bytes);
                }
            }
            find_account_id_in_composite(&variant.values)
        }
        ValueDef::Composite(composite) => find_account_id_in_composite(composite),
        ValueDef::Primitive(scale_value::Primitive::U256(bytes))
        | ValueDef::Primitive(scale_value::Primitive::I256(bytes)) => Some(*bytes),
        ValueDef::Primitive(scale_value::Primitive::String(value)) => {
            AccountId32::from_str(value).ok().map(|id| id.0)
        }
        _ => None,
    }
}

fn find_account_id_in_composite<C>(composite: &Composite<C>) -> Option<[u8; 32]> {
    if let Some(bytes) = composite_as_u8_32(composite) {
        return Some(bytes);
    }

    match composite {
        Composite::Named(fields) => {
            for (_, value) in fields {
                if let Some(bytes) = find_account_id_in_value_any(value) {
                    return Some(bytes);
                }
            }
        }
        Composite::Unnamed(values) => {
            for value in values {
                if let Some(bytes) = find_account_id_in_value_any(value) {
                    return Some(bytes);
                }
            }
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

fn find_named_u128_in_value<C>(value: &Value<C>, keys: &[&str]) -> u128 {
    match &value.value {
        ValueDef::Composite(composite) => find_named_u128_in_composite(composite, keys),
        ValueDef::Variant(variant) => find_named_u128_in_composite(&variant.values, keys),
        _ => 0,
    }
}

fn find_named_u128_in_composite<C>(composite: &Composite<C>, keys: &[&str]) -> u128 {
    match composite {
        Composite::Named(fields) => {
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
        Composite::Unnamed(values) => values
            .iter()
            .map(|v| find_named_u128_in_value(v, keys))
            .max()
            .unwrap_or(0),
    }
}

fn find_tip_in_value<C>(value: &Value<C>) -> Option<u128> {
    match &value.value {
        ValueDef::Composite(composite) => find_tip_in_composite(composite),
        ValueDef::Variant(variant) => find_tip_in_composite(&variant.values),
        _ => None,
    }
}

fn find_tip_in_composite<C>(composite: &Composite<C>) -> Option<u128> {
    match composite {
        Composite::Named(fields) => {
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
        Composite::Unnamed(values) => {
            for val in values {
                if let Some(tip) = find_tip_in_value(val) {
                    return Some(tip);
                }
            }
        }
    }
    None
}

fn extract_u128<C>(value: &Value<C>) -> Option<u128> {
    match &value.value {
        ValueDef::Primitive(p) => p.as_u128().or_else(|| match p {
            scale_value::Primitive::U256(bytes) => {
                // SCALE integers are little-endian.
                let mut high = [0u8; 16];
                high.copy_from_slice(&bytes[16..]);
                if high.iter().any(|b| *b != 0) {
                    return None;
                }
                let mut low = [0u8; 16];
                low.copy_from_slice(&bytes[..16]);
                Some(u128::from_le_bytes(low))
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
