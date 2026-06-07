use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use lockbox_share_protocol::{ServerStatus, TopologyRoute, TopologyServer};
use lockbox_share_server::install::{install_systemd, print_status, uninstall_systemd};
use lockbox_share_server::server::run_server;
use lockbox_share_server::server_log::log_server_event;
use lockbox_share_server::store::{ServerConfig, ShareStore};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            log_server_event(format!("command failed: {err}"));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("run") | None => {
            let config = config_from_args(args.collect())?;
            let bind = config.bind_addr.clone();
            let store = Arc::new(ShareStore::open(config)?);
            run_server(&bind, store)?;
        }
        Some("install") => install_systemd(args.any(|arg| arg == "--force-config"))?,
        Some("uninstall") => uninstall_systemd(args.any(|arg| arg == "--purge-data"))?,
        Some("status") => print_status()?,
        Some("resync-peer") => {
            let (mut config_args, peer_url) = split_peer_url_args(args.collect())?;
            let config = config_from_args(std::mem::take(&mut config_args))?;
            let store = ShareStore::open(config)?;
            let sent = store.resync_peer(&peer_url)?;
            println!("resynced_live_shares={sent}");
        }
        Some("bench-store") => {
            let config = config_from_args(args.collect())?;
            lockbox_share_server::store::bench_store(config)?;
        }
        Some("bench-http") => {
            let config = config_from_args(args.collect())?;
            lockbox_share_server::server::bench_http(config)?;
        }
        Some("bench-http-fetch") => {
            let config = config_from_args(args.collect())?;
            lockbox_share_server::server::bench_http_fetch(config)?;
        }
        Some("bench-http-flow") => {
            let config = config_from_args(args.collect())?;
            lockbox_share_server::server::bench_http_flow(config)?;
        }
        Some("--help") | Some("-h") | Some("help") => print_help(),
        Some(other) => {
            return Err(format!("unknown command `{other}`").into());
        }
    }
    Ok(())
}

fn print_help() {
    println!("Usage:");
    println!("  lockbox-share-server run [--config PATH] [--bind ADDR] [--state-dir PATH]");
    println!("  lockbox-share-server install [--force-config]");
    println!("  lockbox-share-server uninstall [--purge-data]");
    println!("  lockbox-share-server status");
    println!("  lockbox-share-server resync-peer [--config PATH] --peer-url URL");
    println!("  lockbox-share-server bench-store [--state-dir PATH]");
    println!("  lockbox-share-server bench-http [--state-dir PATH]");
    println!("  lockbox-share-server bench-http-fetch [--state-dir PATH]");
    println!("  lockbox-share-server bench-http-flow [--state-dir PATH]");
    println!();
    println!("Options:");
    println!("  --config PATH         Read server config file");
    println!("  --server-id N          Server routing digit, 0..9, default 0");
    println!("  --cluster-id ID        Public topology cluster id");
    println!("  --public-url URL       Public /v1/share URL for this server");
    println!("  --topology-version N   Public topology version");
    println!("  --topology-server ID=URL[,STATUS]  Add server to public topology");
    println!("  --route OWNER=PRIMARY[,FAILOVER...]  Add owner routing rule");
    println!("  --replication-token TOKEN  Shared peer replication token");
    println!("  --replication-peer-url URL  Peer /v1/replicate URL");
    println!("  --peer-url URL        Peer /v1/replicate URL for resync-peer");
    println!("  --origin-epoch N      Local replication epoch");
    println!("  --promoted-owner N    Serve replicated shares for owner id N");
    println!("  --share-code-digits N  Random code body length, clamped to 6..12");
    println!("  --requests N           Benchmark request count");
    println!("  --payload-bytes N      Benchmark payload size");
    println!("  --concurrency N        Benchmark concurrency");
    println!("  --preload-shares N     Benchmark live shares to create before timing");
    println!("  --compact-min-bytes N  Segment size before background compaction");
    println!("  --rate-limit-per-minute N  Per-IP request rate, 0 disables");
    println!("  --rate-limit-burst N       Per-IP burst capacity");
    println!("  --verification-email-command PATH  Command called as PATH <email> <url>");
    println!("  --verification-email-rate-limit-per-hour N");
    println!("  --verification-email-ip-rate-limit-per-hour N");
}

fn split_peer_url_args(
    args: Vec<String>,
) -> Result<(Vec<String>, String), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut peer_url = None;
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == "--peer-url" {
            index += 1;
            peer_url = Some(
                args.get(index)
                    .ok_or("missing value for --peer-url")?
                    .to_string(),
            );
        } else {
            out.push(args[index].clone());
        }
        index += 1;
    }
    Ok((out, peer_url.ok_or("missing --peer-url")?))
}

fn config_from_args(args: Vec<String>) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut config = ServerConfig::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" => {
                index += 1;
                config.bind_addr = args
                    .get(index)
                    .ok_or("missing value for --bind")?
                    .to_string();
            }
            "--state-dir" => {
                index += 1;
                config.state_dir = PathBuf::from(args.get(index).ok_or("missing value")?);
            }
            "--config" => {
                index += 1;
                apply_config_file(&mut config, args.get(index).ok_or("missing value")?)?;
            }
            "--developer" => config.developer_mode = true,
            "--server-id" => {
                index += 1;
                config.server_id = args
                    .get(index)
                    .ok_or("missing value for --server-id")?
                    .parse()?;
            }
            "--cluster-id" => {
                index += 1;
                config.cluster_id = args
                    .get(index)
                    .ok_or("missing value for --cluster-id")?
                    .to_string();
            }
            "--public-url" => {
                index += 1;
                config.public_url = Some(
                    args.get(index)
                        .ok_or("missing value for --public-url")?
                        .to_string(),
                );
            }
            "--topology-version" => {
                index += 1;
                config.topology_version = args
                    .get(index)
                    .ok_or("missing value for --topology-version")?
                    .parse()?;
            }
            "--topology-server" => {
                index += 1;
                config.topology_servers.push(parse_topology_server(
                    args.get(index).ok_or("missing value")?,
                )?);
            }
            "--route" => {
                index += 1;
                config.topology_routes.push(parse_topology_route(
                    args.get(index).ok_or("missing value")?,
                )?);
            }
            "--replication-token" => {
                index += 1;
                config.replication_token = Some(
                    args.get(index)
                        .ok_or("missing value for --replication-token")?
                        .to_string(),
                );
            }
            "--replication-peer-url" => {
                index += 1;
                config.replication_peer_urls.push(
                    args.get(index)
                        .ok_or("missing value for --replication-peer-url")?
                        .to_string(),
                );
            }
            "--origin-epoch" => {
                index += 1;
                config.origin_epoch = args
                    .get(index)
                    .ok_or("missing value for --origin-epoch")?
                    .parse()?;
            }
            "--promoted-owner" => {
                index += 1;
                config
                    .promoted_owner_ids
                    .push(args.get(index).ok_or("missing value")?.parse()?);
            }
            "--requests" => {
                index += 1;
                config.benchmark_requests = args
                    .get(index)
                    .ok_or("missing value for --requests")?
                    .parse()?;
            }
            "--payload-bytes" => {
                index += 1;
                config.benchmark_payload_bytes = args
                    .get(index)
                    .ok_or("missing value for --payload-bytes")?
                    .parse()?;
            }
            "--concurrency" => {
                index += 1;
                config.benchmark_concurrency = args
                    .get(index)
                    .ok_or("missing value for --concurrency")?
                    .parse()?;
            }
            "--preload-shares" => {
                index += 1;
                config.benchmark_preload_shares = args
                    .get(index)
                    .ok_or("missing value for --preload-shares")?
                    .parse()?;
            }
            "--share-code-digits" => {
                index += 1;
                config.share_code_digits = args
                    .get(index)
                    .ok_or("missing value for --share-code-digits")?
                    .parse()?;
            }
            "--compact-min-bytes" => {
                index += 1;
                config.compact_min_bytes = args
                    .get(index)
                    .ok_or("missing value for --compact-min-bytes")?
                    .parse()?;
            }
            "--rate-limit-per-minute" => {
                index += 1;
                config.rate_limit_per_minute = args
                    .get(index)
                    .ok_or("missing value for --rate-limit-per-minute")?
                    .parse()?;
            }
            "--rate-limit-burst" => {
                index += 1;
                config.rate_limit_burst = args
                    .get(index)
                    .ok_or("missing value for --rate-limit-burst")?
                    .parse()?;
            }
            "--verification-email-command" => {
                index += 1;
                config.verification_email_command = Some(
                    args.get(index)
                        .ok_or("missing value for --verification-email-command")?
                        .to_string(),
                );
            }
            "--verification-email-rate-limit-per-hour" => {
                index += 1;
                config.verification_email_rate_limit_per_hour = args
                    .get(index)
                    .ok_or("missing value for --verification-email-rate-limit-per-hour")?
                    .parse()?;
            }
            "--verification-email-ip-rate-limit-per-hour" => {
                index += 1;
                config.verification_email_ip_rate_limit_per_hour = args
                    .get(index)
                    .ok_or("missing value for --verification-email-ip-rate-limit-per-hour")?
                    .parse()?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown option `{other}`").into()),
        }
        index += 1;
    }
    Ok(config)
}

fn apply_config_file(
    config: &mut ServerConfig,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for (line_no, raw_line) in fs::read_to_string(path)?.lines().enumerate() {
        let line = raw_line
            .split_once('#')
            .map(|(value, _)| value)
            .unwrap_or(raw_line)
            .trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{path}:{}: expected key = value", line_no + 1))?;
        apply_config_value(config, key.trim(), parse_config_value(value.trim())?)
            .map_err(|err| format!("{path}:{}: {err}", line_no + 1))?;
    }
    Ok(())
}

fn parse_config_value(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = value.trim();
    if let Some(value) = value.strip_prefix('"') {
        let value = value
            .strip_suffix('"')
            .ok_or("unterminated quoted config value")?;
        return Ok(value.to_string());
    }
    Ok(value.to_string())
}

fn apply_config_value(
    config: &mut ServerConfig,
    key: &str,
    value: String,
) -> Result<(), Box<dyn std::error::Error>> {
    match key {
        "bind_addr" => config.bind_addr = value,
        "state_dir" => config.state_dir = PathBuf::from(value),
        "server_id" => config.server_id = value.parse()?,
        "cluster_id" => config.cluster_id = value,
        "public_url" => {
            config.public_url = if value.is_empty() { None } else { Some(value) };
        }
        "topology_version" => config.topology_version = value.parse()?,
        "topology_server" => config.topology_servers.push(parse_topology_server(&value)?),
        "route" => config.topology_routes.push(parse_topology_route(&value)?),
        "replication_token" => {
            config.replication_token = if value.is_empty() { None } else { Some(value) };
        }
        "replication_peer_url" => config.replication_peer_urls.push(value),
        "origin_epoch" => config.origin_epoch = value.parse()?,
        "promoted_owner" => config.promoted_owner_ids.push(value.parse()?),
        "share_code_digits" => config.share_code_digits = value.parse()?,
        "compact_min_bytes" => config.compact_min_bytes = value.parse()?,
        "rate_limit_per_minute" => config.rate_limit_per_minute = value.parse()?,
        "rate_limit_burst" => config.rate_limit_burst = value.parse()?,
        "verification_email_command" => {
            config.verification_email_command = if value.is_empty() { None } else { Some(value) };
        }
        "verification_email_rate_limit_per_hour" => {
            config.verification_email_rate_limit_per_hour = value.parse()?;
        }
        "verification_email_ip_rate_limit_per_hour" => {
            config.verification_email_ip_rate_limit_per_hour = value.parse()?;
        }
        "max_payload_bytes" => config.max_payload_bytes = value.parse()?,
        "default_ttl_seconds" => {
            config.default_ttl = Duration::from_secs(value.parse()?);
        }
        "max_ttl_seconds" => {
            config.max_ttl = Duration::from_secs(value.parse()?);
        }
        "shard_count" => config.shard_count = value.parse()?,
        "max_fetches_per_share" => config.max_fetches_per_share = value.parse()?,
        "index_cache_entries" => config.index_cache_entries = value.parse()?,
        "developer_mode" => config.developer_mode = value.parse()?,
        other => return Err(format!("unknown config key `{other}`").into()),
    }
    Ok(())
}

fn parse_topology_server(value: &str) -> Result<TopologyServer, Box<dyn std::error::Error>> {
    let (id, rest) = value
        .split_once('=')
        .ok_or("topology server must be ID=URL[,STATUS]")?;
    let mut parts = rest.splitn(2, ',');
    let url = parts.next().unwrap_or_default().to_string();
    let status = match parts.next().unwrap_or("active") {
        "active" => ServerStatus::Active,
        "standby" => ServerStatus::Standby,
        "promoted" => ServerStatus::Promoted,
        "disabled" => ServerStatus::Disabled,
        other => return Err(format!("unknown server status `{other}`").into()),
    };
    Ok(TopologyServer {
        id: id.parse()?,
        url,
        status,
    })
}

fn parse_topology_route(value: &str) -> Result<TopologyRoute, Box<dyn std::error::Error>> {
    let (owner_id, rest) = value
        .split_once('=')
        .ok_or("route must be OWNER=PRIMARY[,FAILOVER...]")?;
    let ids = rest
        .split(',')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()?;
    let Some((primary_id, failover_ids)) = ids.split_first() else {
        return Err("route must include a primary server id".into());
    };
    Ok(TopologyRoute {
        owner_id: owner_id.parse()?,
        primary_id: *primary_id,
        failover_ids: failover_ids.to_vec(),
    })
}
