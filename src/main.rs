mod download;
mod gzip;

use clap::Parser;
use ipnet::{IpAdd, IpNet};
use bgpkit_parser::BgpkitParser;
use std::collections::HashSet;
use std::fs::{File};
use std::io::{self, BufReader};
use std::str::FromStr;
use std::error::Error;
use std::net::IpAddr;
use std::time::Duration;
use crate::download::{download_cached_gzip};

#[allow(unused_imports)]
use log::{debug, info, warn, error};

#[cfg(feature = "diagnostic_logging")]
fn init_logger() {
    env_logger::init();
}

#[cfg(not(feature = "diagnostic_logging"))]
fn init_logger() {
    // No-op when diagnostic logging is not enabled
}

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

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();
    init_logger();

    // Check if the MRT file is provided or needs to be downloaded
    let mrt_file_path = match opts.mrt_file {
        Some(file) => file,
        None => {
            let url = "https://data.ris.ripe.net/rrc01/latest-bview.gz";
            let output_file_gzip = "latest-bview.gz";
            let output_file_mrt = "latest-bview.mrt";
            let verify_etag_interval = Duration::from_secs(86400);

            debug!("MRT file not specified, using {}", url);
            download_cached_gzip(url, output_file_gzip, output_file_mrt, verify_etag_interval)?
        }
    };

    let origin_asns = opts.origin_asns.iter().cloned().collect();
    let mut input_file = File::open(&mrt_file_path)?;
    let mut prefixes = scan_prefixes(&mut input_file, &origin_asns, opts.filters.ipv4_only, opts.filters.ipv6_only)?;
    
    // Exclude subnets if specified
    if let Some(exclude_subnets) = opts.exclude_subnets {
        debug!("Applying excluded subnets {:?}", exclude_subnets);
        for exclude_net_str in exclude_subnets {
            let exclude_net = IpNet::from_str(&exclude_net_str)?;
            prefixes = prefixes.into_iter().flat_map(|prefix| exclude_subnet(prefix, exclude_net)).collect();
        }
    }

    if opts.json {
        serde_json::to_writer(io::stdout(), &prefixes)?;
    } else {
        for prefix in prefixes {
            println!("{}", prefix);
        }
    }
    
    Ok(())
}

fn scan_prefixes(
    file: &mut File,
    origin_asns: &HashSet<u32>,
    ipv4_only: bool,
    ipv6_only: bool
) -> Result<Vec<IpNet>, Box<dyn Error>> {
    let mut reader = BufReader::new(file.try_clone()?);
    let mut parser = BgpkitParser::from_reader(&mut reader);

    match (ipv4_only, ipv6_only) {
        (true, false) => {
            debug!("Filtering for only IPv4");
            parser = parser.add_filter("ip_version", "ipv4").expect("Failed to add IPv4 filter");
        }
        (false, true) => {
            debug!("Filtering for only IPv6");
            parser = parser.add_filter("ip_version", "ipv6").expect("Failed to add IPv6 filter");
        }
        _ => {}
    }

    //TODO: Test the performance of filtering per AS number specified with the native AS origin filter
    //TODO:
    debug!("Filtering for only announce records");
    parser = parser.add_filter("type", "announce")?;

    let before = instant::Instant::now();

    debug!("Scanning MRT file for prefixes associated with AS numbers {:?}...", origin_asns);
    let mut prefixes = HashSet::new();
    for elem in parser.into_elem_iter() {
        if let Some(elem_origin_asns) = &elem.origin_asns {
            if elem_origin_asns.iter().any(|asn| origin_asns.contains(&asn.to_u32())) {
                if prefixes.insert(elem.prefix.prefix) {
                    debug!("Found new matching prefix {}", elem.prefix.prefix);
                }
            }
        }
    }

    let after = instant::Instant::now();

    debug!("Finished scanning MRT file after {} seconds", (after - before).as_secs());

    Ok(prefixes.iter().cloned().collect())
}

fn exclude_subnet(net: IpNet, excluded_net: IpNet) -> Vec<IpNet> {
    let mut result = Vec::new();

    // If excluded_net is not within net, return the whole net
    if !net.contains(&excluded_net.network()) || !net.contains(&excluded_net.broadcast()) {
        result.push(net);
        return result;
    }

    // Check if net and excluded_net are the same
    if net == excluded_net {
        return result; // Empty result as the entire net is excluded
    }

    debug!("Excluded subnet {} is a subset of {}", excluded_net, net);

    // If net contains excluded_net, we need to split net into subnets
    // Generate subnets by splitting the net
    let left_subnet = IpNet::new(net.network(), net.prefix_len() + 1).unwrap();
    let next_ip = match left_subnet.broadcast() {
        IpAddr::V4(ip) => IpAddr::V4(ip.saturating_add(1)),
        IpAddr::V6(ip) => IpAddr::V6(ip.saturating_add(1)),
    };
    let right_subnet = IpNet::new(next_ip, left_subnet.prefix_len() + 1).unwrap();

    if left_subnet.contains(&excluded_net.network()) {
        // Exclude from the left subnet
        result.extend(exclude_subnet(left_subnet, excluded_net));
        result.push(right_subnet); // Add the right subnet as it is
    } else if right_subnet.contains(&excluded_net.network()) {
        // Exclude from the right subnet
        result.push(left_subnet); // Add the left subnet as it is
        result.extend(exclude_subnet(right_subnet, excluded_net));
    }

    result
}


