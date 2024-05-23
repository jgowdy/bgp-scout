mod download;
mod gzip;

use bgpkit_parser::BgpkitParser;
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, BufReader};
use std::str::FromStr;
use std::time::Duration;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Find netblocks based on provided parameters
    FindNetblocks {
        #[arg(required = true, index = 1, value_delimiter = ',')]
        origin_asns: Vec<u32>,

        /// MRT file, conflicts with specifying RIPE RRC or URL
        #[clap(short = 'f', long, conflicts_with = "rrc", conflicts_with = "url")]
        mrt_file: Option<String>,

        /// Specify RIPE RRC server number (00-25) [default: 01], conflicts with specifying URL or MRT file directly
        #[clap(short = 'r', long, conflicts_with = "url", conflicts_with = "mrt_file", value_parser = clap::value_parser!(u8).range(0..=25))]
        rrc: Option<u8>,

        /// Specify an entire URL, conflicts with specifying RRC or MRT file directly
        #[clap(long, conflicts_with = "rrc", conflicts_with = "mrt_file")]
        url: Option<String>,

        /// Exclude specified subnets from results
        #[clap(long, value_delimiter = ',')]
        exclude_subnets: Option<Vec<String>>,

        /// Output as JSON objects
        #[clap(long)]
        json: bool,

        /// Output IP addresses as ranges
        #[clap(long, default_value_t = false)]
        ip_ranges: bool,

        /// Verification interval for cache, in seconds
        #[clap(long, default_value_t = 86400)]
        verify_cache_seconds: u64,

        #[clap(flatten)]
        filters: Filters,
    },
    /// Check if one netblock contains another
    NetblockContains {
        /// The netblock to search for
        #[clap(value_parser)]
        needle: String,

        /// The netblock to check containment
        #[clap(value_parser)]
        haystack: String,
    },
}

#[derive(Parser, Debug)]
struct Filters {
    /// Filter by IPv4 only
    #[clap(short = '4', long, conflicts_with("ipv6_only"))]
    ipv4_only: bool,

    /// Filter by IPv6 only
    #[clap(short = '6', long, conflicts_with("ipv4_only"))]
    ipv6_only: bool,
}

fn prefix_to_range(prefix: &IpNet) -> String {
    format!("{}-{}", prefix.network(), prefix.broadcast())
}

fn transform_subnets_string(subnets: &[IpNet], ranges: bool) -> Vec<String> {
    let mut result = Vec::new();
    for subnet in subnets {
        if ranges {
            result.push(prefix_to_range(subnet));
        } else {
            result.push(subnet.to_string());
        }
    }
    result
}

fn main() -> Result<(), Box<dyn Error>> {
    init_logger();
    let cli = Cli::parse();

    match &cli.command {
        Commands::FindNetblocks {
            origin_asns,
            mrt_file,
            json,
            exclude_subnets,
            ip_ranges,
            verify_cache_seconds,
            filters,
            rrc,
            url,
        } => {
            let origin_asns = origin_asns.iter().copied().collect();
            let excluded_subnets = transform_subnets_ipnet(exclude_subnets);

            let mrt_file_path = if let Some(file) = mrt_file {
                file.clone()
            } else {
                let download_url = match (url, rrc) {
                    (Some(u), _) => u.clone(),
                    (None, rrc) => format!(
                        "https://data.ris.ripe.net/rrc{:02}/latest-bview.gz",
                        rrc.unwrap_or(1)
                    ),
                };

                let mut hasher = DefaultHasher::new();
                download_url.hash(&mut hasher);
                let hash = hasher.finish();

                fs::create_dir_all(".cache")?;
                let output_file_gzip = format!(".cache/{hash:x}-latest-bview.gz");
                let output_file_mrt = format!(".cache/{hash:x}-latest-bview.mrt");
                let verify_cache_interval = Duration::from_secs(*verify_cache_seconds);

                debug!("Using {download_url} for MRT source");
                download::cached_gzip(
                    &download_url,
                    &output_file_gzip,
                    &output_file_mrt,
                    verify_cache_interval,
                )?
            };

            let mrt_file = File::open(mrt_file_path)?;
            let prefixes = scan_prefixes(
                &mrt_file,
                &origin_asns,
                filters.ipv4_only,
                filters.ipv6_only,
            )?;
            let prefixes_len = prefixes.len();

            let filtered_prefixes = match excluded_subnets {
                Some(excluded) => crate::exclude_subnets(&prefixes, excluded)?,
                None => prefixes,
            };
            trace!("Filtered prefixes after excluded subnets:\n{filtered_prefixes:#?}");
            debug!(
                "Prefixes before excluded subnet filtering: {} After: {}",
                prefixes_len,
                filtered_prefixes.len()
            );

            let aggregated_prefixes = IpNet::aggregate(&filtered_prefixes);

            trace!("Aggregated prefixes:\n{aggregated_prefixes:#?}");
            debug!(
                "Prefixes before aggregation: {} After: {}",
                filtered_prefixes.len(),
                aggregated_prefixes.len()
            );

            render_output(&aggregated_prefixes, *json, *ip_ranges)?;
        }
        Commands::NetblockContains { needle, haystack } => {
            let needle_net: IpNet = IpNet::from_str(needle)?;
            let haystack_net: IpNet = IpNet::from_str(haystack)?;
            if haystack_net.contains(&needle_net.addr()) {
                println!("{haystack} contains {needle}");
            } else {
                println!("{haystack} does not contain {needle}");
            }
        }
    }

    Ok(())
}

fn render_output(prefixes: &[IpNet], json: bool, ranges: bool) -> Result<(), Box<dyn Error>> {
    let mut output = io::stdout();
    let prefix_strings = transform_subnets_string(prefixes, ranges);
    if json {
        serde_json::to_writer(&mut output, &prefix_strings)?;
    } else {
        for prefix in prefix_strings {
            println!("{prefix}");
        }
    }
    Ok(())
}

fn transform_subnets_ipnet(opts: &Option<Vec<String>>) -> Option<Vec<IpNet>> {
    match opts {
        Some(subnets) if !subnets.is_empty() => {
            let parsed_subnets: Vec<IpNet> = subnets
                .iter()
                .filter_map(|s| IpNet::from_str(s).ok())
                .collect();

            if parsed_subnets.is_empty() {
                None
            } else {
                Some(parsed_subnets)
            }
        }
        _ => None,
    }
}

fn scan_prefixes(
    file: &File,
    origin_asns: &HashSet<u32>,
    ipv4_only: bool,
    ipv6_only: bool,
) -> Result<Vec<IpNet>, Box<dyn Error>> {
    let mut reader = BufReader::new(file);
    let mut parser = BgpkitParser::from_reader(&mut reader);

    match (ipv4_only, ipv6_only) {
        (true, false) => {
            debug!("Filtering for only IPv4");
            parser = parser
                .add_filter("ip_version", "ipv4")
                .expect("Failed to add IPv4 filter");
        }
        (false, true) => {
            debug!("Filtering for only IPv6");
            parser = parser
                .add_filter("ip_version", "ipv6")
                .expect("Failed to add IPv6 filter");
        }
        _ => {}
    }

    debug!("Filtering for only announce records");
    parser = parser.add_filter("type", "announce")?;

    let before = instant::Instant::now();

    debug!(
        "Scanning MRT file for prefixes associated with AS numbers {:?}...",
        origin_asns
    );
    let mut prefixes = HashSet::new();

    if origin_asns.len() == 1 {
        // There's only one AS number, use bgpkit-parser native filter as it's faster
        debug!("Using native filtering for origin AS");
        parser = parser.add_filter("origin_asn", "53429")?;
        for elem in parser.into_elem_iter() {
            if prefixes.insert(elem.prefix.prefix) {
                debug!("Found new matching prefix {}", elem.prefix.prefix);
            }
        }
    } else {
        // Since bgpkit-parser doesn't support filtering on more than one origin, filter manually
        debug!("Using standard filtering for origin AS");
        for elem in parser.into_elem_iter() {
            if let Some(elem_origin_asns) = &elem.origin_asns {
                if elem_origin_asns
                    .iter()
                    .any(|asn| origin_asns.contains(&asn.to_u32()))
                    && prefixes.insert(elem.prefix.prefix)
                {
                    trace!("Found new matching prefix {}", elem.prefix.prefix);
                }
            }
        }
    }

    let after = instant::Instant::now();

    #[allow(clippy::cast_precision_loss)]
    let elapsed_seconds = ((after - before).as_millis() as f64) / 1000.0;

    debug!(
        "Finished scanning MRT file after {} seconds",
        elapsed_seconds
    );

    Ok(prefixes.iter().copied().collect())
}

fn exclude_subnets(
    prefixes: &[IpNet],
    excluded_subnets: Vec<IpNet>,
) -> Result<Vec<IpNet>, Box<dyn Error>> {
    let mut result = Vec::new();
    let excluded_set: HashSet<IpNet> = excluded_subnets.into_iter().collect();

    'outer: for prefix in prefixes {
        for excluded in &excluded_set {
            if excluded.contains(prefix) {
                debug!(
                    "Prefix {} is entirely contained by excluded subnet {}, skipping it.",
                    prefix, excluded
                );
                continue 'outer;
            } else if prefix.contains(excluded) {
                debug!(
                    "Prefix {} contains excluded subnet {}, splitting it.",
                    prefix, excluded
                );
                let new_prefix_len = excluded.prefix_len();
                for subnet in prefix.subnets(new_prefix_len)? {
                    if subnet == *excluded {
                        debug!(
                            "Excluding subnet {} from split of prefix {}.",
                            subnet, prefix
                        );
                    } else {
                        debug!("Adding subnet {} from split of prefix {}.", subnet, prefix);
                        result.push(subnet);
                    }
                }
                continue 'outer;
            }
        }
        trace!("Adding unaffected prefix: {}", prefix);
        result.push(*prefix);
    }

    Ok(result)
}

#[cfg(feature = "diagnostic_logging")]
fn init_logger() {
    env_logger::init();
}

#[cfg(not(feature = "diagnostic_logging"))]
fn init_logger() {
    // No-op when diagnostic logging is not enabled
}
