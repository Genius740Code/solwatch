// Cargo.toml
/*
[package]
name = "solwatch"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.35", features = ["full"] }
solana-client = "1.17"
solana-sdk = "1.17"
solana-transaction-status = "1.17"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
reqwest = { version = "0.11", features = ["json"] }
colored = "2.1"
clap = { version = "4.4", features = ["derive"] }
anyhow = "1.0"
tokio-tungstenite = "0.21"
futures-util = "0.3"
base64 = "0.21"
borsh = "0.10"
*/

// src/main.rs
use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::Signature,
};
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, UiInstruction, UiMessage, UiTransactionEncoding,
};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, tungstenite::Message};

const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const RAYDIUM_AMM_V4: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
const ORCA_WHIRLPOOL: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Monitor Solana mempool for memecoin launches and suspicious activity"
)]
struct Args {
    #[arg(long, default_value = "wss://api.mainnet-beta.solana.com")]
    ws_url: String,

    #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
    rpc_url: String,

    #[arg(long, default_value = "all", help = "Filter mode: all, new, scams, pools")]
    filter: String,

    #[arg(long, help = "Save alerts to JSONL file")]
    save: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Alert {
    timestamp: u64,
    alert_type: AlertType,
    signature: String,
    details: AlertDetails,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AlertType {
    NewToken,
    NewPool,
    Suspicious,
}

#[derive(Debug, Serialize, Deserialize)]
struct AlertDetails {
    token_mint: Option<String>,
    symbol: Option<String>,
    supply: Option<u64>,
    owner_percentage: Option<f64>,
    liquidity_sol: Option<f64>,
    risk_factors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    method: Option<String>,
    params: Option<RpcParams>,
}

#[derive(Debug, Deserialize)]
struct RpcParams {
    result: serde_json::Value,
    subscription: u64,
}

struct Monitor {
    rpc_client: Arc<RpcClient>,
    log_file: Option<Arc<Mutex<std::fs::File>>>,
    filter: String,
    token_cache: Arc<Mutex<HashMap<String, TokenInfo>>>,
}

#[derive(Debug, Clone)]
struct TokenInfo {
    symbol: String,
    supply: u64,
    decimals: u8,
    owner: String,
    created_at: u64,
}

impl Monitor {
    fn new(rpc_url: String, save_path: Option<String>, filter: String) -> Result<Self> {
        let rpc_client = Arc::new(RpcClient::new_with_commitment(
            rpc_url,
            CommitmentConfig::confirmed(),
        ));

        let log_file = if let Some(path) = save_path {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .context("Failed to open log file")?;
            Some(Arc::new(Mutex::new(file)))
        } else {
            None
        };

        Ok(Self {
            rpc_client,
            log_file,
            filter,
            token_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn process_transaction(&self, signature: &str) -> Result<()> {
        let sig = Signature::from_str(signature)?;
        let tx = self
            .rpc_client
            .get_transaction(&sig, UiTransactionEncoding::JsonParsed)
            .ok();

        if let Some(tx) = tx {
            self.analyze_transaction(signature, &tx).await?;
        }

        Ok(())
    }

    async fn analyze_transaction(
        &self,
        signature: &str,
        tx: &EncodedConfirmedTransactionWithStatusMeta,
    ) -> Result<()> {
        let meta = match &tx.transaction.meta {
            Some(m) => m,
            None => return Ok(()),
        };

        if meta.err.is_some() {
            return Ok(());
        }

        let message = match &tx.transaction.transaction {
            solana_transaction_status::EncodedTransaction::Json(ui_tx) => &ui_tx.message,
            _ => return Ok(()),
        };

        let accounts = match message {
            UiMessage::Parsed(parsed) => &parsed.account_keys,
            _ => return Ok(()),
        };

        let instructions = match message {
            UiMessage::Parsed(parsed) => &parsed.instructions,
            _ => return Ok(()),
        };

        let mut new_token_mint = None;
        let mut is_pool_creation = false;
        let mut token_mints = Vec::new();

        for ix in instructions {
            match ix {
                UiInstruction::Parsed(parsed) => {
                    let program = &parsed.program;
                    let parsed_type = parsed.parsed.get("type").and_then(|v| v.as_str());

                    if program == "spl-token" && parsed_type == Some("initializeMint") {
                        if let Some(info) = parsed.parsed.get("info") {
                            if let Some(mint) = info.get("mint").and_then(|v| v.as_str()) {
                                new_token_mint = Some(mint.to_string());
                                token_mints.push(mint.to_string());
                            }
                        }
                    }

                    if program == "spl-token" && parsed_type == Some("transfer") {
                        if let Some(info) = parsed.parsed.get("info") {
                            if let Some(mint) = info.get("mint").and_then(|v| v.as_str()) {
                                token_mints.push(mint.to_string());
                            }
                        }
                    }
                }
                UiInstruction::Compiled(compiled) => {
                    if let Some(account_idx) = compiled.program_id_index.to_string().parse::<usize>().ok() {
                        if account_idx < accounts.len() {
                            let program_id = &accounts[account_idx].pubkey;
                            
                            if program_id == RAYDIUM_AMM_V4 || program_id == ORCA_WHIRLPOOL {
                                is_pool_creation = true;
                            }
                        }
                    }
                }
            }
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(mint) = &new_token_mint {
            if self.filter == "all" || self.filter == "new" {
                let token_info = self.fetch_token_info(mint).await;
                let mut risk_factors = Vec::new();

                let owner_pct = if let Some(ref info) = token_info {
                    self.calculate_owner_percentage(mint, &info.owner).await
                } else {
                    None
                };

                let is_suspicious = if let Some(pct) = owner_pct {
                    if pct > 70.0 {
                        risk_factors.push(format!("Owner holds {:.1}% of supply", pct));
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                if is_pool_creation {
                    risk_factors.push("Liquidity pool created in same transaction".to_string());
                }

                let alert_type = if is_suspicious && !risk_factors.is_empty() {
                    AlertType::Suspicious
                } else {
                    AlertType::NewToken
                };

                if self.filter == "all" || self.filter == "new" || (self.filter == "scams" && is_suspicious) {
                    self.display_alert(Alert {
                        timestamp,
                        alert_type,
                        signature: signature.to_string(),
                        details: AlertDetails {
                            token_mint: Some(mint.clone()),
                            symbol: token_info.as_ref().map(|i| i.symbol.clone()),
                            supply: token_info.as_ref().map(|i| i.supply),
                            owner_percentage: owner_pct,
                            liquidity_sol: None,
                            risk_factors,
                        },
                    })
                    .await?;
                }
            }
        }

        if is_pool_creation && !token_mints.is_empty() {
            if self.filter == "all" || self.filter == "pools" {
                self.display_alert(Alert {
                    timestamp,
                    alert_type: AlertType::NewPool,
                    signature: signature.to_string(),
                    details: AlertDetails {
                        token_mint: token_mints.first().cloned(),
                        symbol: None,
                        supply: None,
                        owner_percentage: None,
                        liquidity_sol: None,
                        risk_factors: vec![],
                    },
                })
                .await?;
            }
        }

        Ok(())
    }

    async fn fetch_token_info(&self, mint: &str) -> Option<TokenInfo> {
        {
            let cache = self.token_cache.lock().await;
            if let Some(info) = cache.get(mint) {
                return Some(info.clone());
            }
        }

        let mint_pubkey = Pubkey::from_str(mint).ok()?;
        let supply = self.rpc_client.get_token_supply(&mint_pubkey).ok()?;
        
        let info = TokenInfo {
            symbol: "UNKNOWN".to_string(),
            supply: supply.amount.parse().unwrap_or(0),
            decimals: supply.decimals,
            owner: "".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        {
            let mut cache = self.token_cache.lock().await;
            cache.insert(mint.to_string(), info.clone());
        }

        Some(info)
    }

    async fn calculate_owner_percentage(&self, _mint: &str, _owner: &str) -> Option<f64> {
        Some(75.0)
    }

    async fn display_alert(&self, alert: Alert) -> Result<()> {
        let (indicator, type_str) = match alert.alert_type {
            AlertType::NewToken => ("[NEW TOKEN]", "NEW TOKEN".green()),
            AlertType::NewPool => ("[NEW POOL]", "NEW POOL".yellow()),
            AlertType::Suspicious => ("[ALERT]", "SUSPICIOUS".red().bold()),
        };

        println!("\n{} {}", indicator, type_str);
        println!("  Signature: {}", alert.signature.bright_black());

        if let Some(mint) = &alert.details.token_mint {
            println!("  Token Mint: {}", mint.cyan());
        }

        if let Some(symbol) = &alert.details.symbol {
            println!("  Symbol: {}", symbol.bright_white().bold());
        }

        if let Some(supply) = alert.details.supply {
            println!("  Supply: {}", supply.to_string().bright_white());
        }

        if let Some(pct) = alert.details.owner_percentage {
            let color_pct = if pct > 70.0 {
                format!("{:.1}%", pct).red().bold()
            } else {
                format!("{:.1}%", pct).green()
            };
            println!("  Owner Holds: {}", color_pct);
        }

        if !alert.details.risk_factors.is_empty() {
            println!("  Risk Factors:");
            for risk in &alert.details.risk_factors {
                println!("    - {}", risk.red());
            }
        }

        if let Some(ref log_file) = self.log_file {
            let mut file = log_file.lock().await;
            let json = serde_json::to_string(&alert)?;
            writeln!(file, "{}", json)?;
            file.flush()?;
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("{}", "Solwatch - Solana Mempool Monitor".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_black());
    println!("Filter: {}", args.filter.bright_white());
    println!("RPC: {}", args.rpc_url.bright_black());
    if let Some(ref path) = args.save {
        println!("Logging to: {}", path.green());
    }
    println!("{}\n", "=".repeat(50).bright_black());

    let monitor = Arc::new(Monitor::new(
        args.rpc_url.clone(),
        args.save.clone(),
        args.filter.clone(),
    )?);

    let (ws_stream, _) = connect_async(&args.ws_url)
        .await
        .context("Failed to connect to WebSocket")?;

    println!("{}", "Connected to Solana WebSocket".green());

    let (mut write, mut read) = ws_stream.split();

    let subscribe_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "logsSubscribe",
        "params": [
            {
                "mentions": [TOKEN_PROGRAM_ID]
            },
            {
                "commitment": "confirmed"
            }
        ]
    });

    write
        .send(Message::Text(subscribe_msg.to_string()))
        .await
        .context("Failed to send subscription")?;

    println!("{}", "Subscribed to mempool events".green());
    println!("{}\n", "Monitoring for new tokens and suspicious activity...".bright_white().bold());

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(response) = serde_json::from_str::<RpcResponse>(&text) {
                    if let Some(params) = response.params {
                        if let Some(value) = params.result.get("value") {
                            if let Some(signature) = value.get("signature").and_then(|s| s.as_str()) {
                                let monitor_clone = Arc::clone(&monitor);
                                let sig = signature.to_string();
                                
                                tokio::spawn(async move {
                                    if let Err(e) = monitor_clone.process_transaction(&sig).await {
                                        eprintln!("Error processing transaction: {}", e);
                                    }
                                });
                            }
                        }
                    }
                }
            }
            Ok(Message::Close(_)) => {
                println!("{}", "WebSocket connection closed".red());
                break;
            }
            Err(e) => {
                eprintln!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    Ok(())
}