mod download;
mod gzip;

use bgpkit_parser::BgpkitParser;
use clap::Parser;
use ipnet::{IpAdd, IpNet};
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

#[allow(unused_imports)]
use log::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Opts {
    #[arg(required = true, index = 1)]
    origin_asns: Vec<u32>,

    /// MRT file URL or local path
    #[clap(short = 'f', long = "mrt-file")]
    mrt_file: Option<String>,

    /// Output as JSON objects
    #[clap(long)]
    json: bool,

    /// Exclude specified subnets
    #[clap(long, value_delimiter = ',')]
    exclude_subnets: Option<Vec<String>>,

    /// Output IP addresses as ranges
    #[clap(long, default_value_t = false)]
    ip_ranges: bool,

    #[clap(flatten)]
    filters: Filters,
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
            result.push(prefix_to_range(&subnet));
        } else {
            result.push(subnet.to_string());
        }
    }
    result
}

fn main() -> Result<(), Box<dyn Error>> {
    init_logger();
    let opts: Opts = Opts::parse();
    let origin_asns = opts.origin_asns.iter().copied().collect();
    let excluded_subnets = transform_subnets_ipnet(opts.exclude_subnets);

    let mrt_file_path = if let Some(file) = opts.mrt_file {
        file
    } else {
        // TODO: Add parameter for which rrc to use
        let url = "https://data.ris.ripe.net/rrc01/latest-bview.gz";
        // TODO: Add which rrc we use to the file name
        let output_file_gzip = "latest-bview.gz";
        let output_file_mrt = "latest-bview.mrt";
        // TODO: Make this configurable via parameter
        let verify_etag_interval = Duration::from_secs(86400);

        debug!("MRT file not specified, using {}", url);
        download::cached_gzip(url, output_file_gzip, output_file_mrt, verify_etag_interval)?
    };

    let mrt_file = File::open(mrt_file_path)?;
    let prefixes = scan_prefixes(
        &mrt_file,
        &origin_asns,
        opts.filters.ipv4_only,
        opts.filters.ipv6_only,
    )?;

    let filtered_prefixes = match excluded_subnets {
        Some(excluded) => exclude_subnets(&prefixes, excluded),
        None => prefixes,
    };

    render_output(&filtered_prefixes, opts.json, opts.ip_ranges)?;

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

fn transform_subnets_ipnet(opts: Option<Vec<String>>) -> Option<Vec<IpNet>> {
    match opts {
        Some(subnets) if !subnets.is_empty() => {
            let parsed_subnets: Vec<IpNet> = subnets
                .into_iter()
                .filter_map(|s| IpNet::from_str(&s).ok())
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

fn exclude_subnets(prefixes: &[IpNet], excluded_subnets: Vec<IpNet>) -> Vec<IpNet> {
    let mut final_prefixes = Vec::new();
    debug!("Applying excluded subnets {:?}", excluded_subnets);

    for exclude_net in excluded_subnets {
        debug!("Searching prefixes for excluded subnet {}", exclude_net);
        final_prefixes.extend(
            prefixes
                .iter()
                .flat_map(|prefix| exclude_subnet(prefix, exclude_net)),
        );
    }
    final_prefixes
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
                    debug!("Found new matching prefix {}", elem.prefix.prefix);
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

fn exclude_subnet(net: &IpNet, excluded_net: IpNet) -> Vec<IpNet> {
    let mut result = Vec::new();

    // If excluded_net is not within net, return the whole net
    if !net.contains(&excluded_net.network()) || !net.contains(&excluded_net.broadcast()) {
        result.push(*net);
        return result;
    }

    // Check if net and excluded_net are the same
    if *net == excluded_net {
        return result; // Empty result as the entire net is excluded
    }

    debug!("Excluded subnet {} is a subset of {}", excluded_net, net);

    // If net contains excluded_net, we need to split net into subnets
    // Generate subnets by splitting the net
    let left_subnet =
        IpNet::new(net.network(), net.prefix_len() + 1).expect("Failed to split left_subnet");
    let next_ip = ipaddr_saturating_add(left_subnet.broadcast());
    let right_subnet =
        IpNet::new(next_ip, left_subnet.prefix_len() + 1).expect("Failed to split right_subnet");

    if left_subnet.contains(&excluded_net.network()) {
        // Exclude from the left subnet
        result.extend(exclude_subnet(&left_subnet, excluded_net));
        result.push(right_subnet); // Add the right subnet as it is
    } else if right_subnet.contains(&excluded_net.network()) {
        // Exclude from the right subnet
        result.push(left_subnet); // Add the left subnet as it is
        result.extend(exclude_subnet(&right_subnet, excluded_net));
    }

    result
}

fn ipaddr_saturating_add(ipaddr: IpAddr) -> IpAddr {
    match ipaddr {
        IpAddr::V4(ip) => IpAddr::V4(ip.saturating_add(1)),
        IpAddr::V6(ip) => IpAddr::V6(ip.saturating_add(1)),
    }
}

#[cfg(feature = "diagnostic_logging")]
fn init_logger() {
    env_logger::init();
}

#[cfg(not(feature = "diagnostic_logging"))]
fn init_logger() {
    // No-op when diagnostic logging is not enabled
}
