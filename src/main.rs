use clap::Parser;
use ipnet::{IpAdd, Ipv4Net};
use bgpkit_parser::BgpkitParser;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufReader, Seek, SeekFrom, Write};
use std::str::FromStr;
use std::error::Error;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Opts {
    /// File path to a MRT file, local or remote.
    #[clap(name = "FILE")]
    file_path: String,

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
    /// Filter by origin AS Numbers (comma-separated list)
    #[clap(short = 'o', long, value_delimiter = ',')]
    origin_asns: Option<Vec<u32>>,

    /// Discover associated ASNs
    #[clap(long)]
    discover_asns: bool,

    /// Filter by IPv4 only
    #[clap(short = '4', long)]
    ipv4_only: bool,

    /// Filter by IPv6 only
    #[clap(short = '6', long)]
    ipv6_only: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();

    let mut origin_asns: HashSet<u32> = match &opts.filters.origin_asns {
        Some(asns) => asns.iter().cloned().collect(),
        None => HashSet::new(),
    };

    let mut input_file = File::open(&opts.file_path)?;

    if opts.filters.discover_asns {
        if origin_asns.is_empty() {
            eprintln!("Error: --origin-asns must be specified when using --discover-asns");
            std::process::exit(1);
        }

        let discovered_asns = discover_associated_asns(&mut input_file, &origin_asns)?;
        println!("Discovered ASNs: {:?}", discovered_asns);
        origin_asns.extend(discovered_asns);

        // Seek back to the beginning of the file
        input_file.seek(SeekFrom::Start(0))?;
    }

    
    let mut prefixes = scan_prefixes(&mut input_file, &origin_asns, opts.filters.ipv4_only, opts.filters.ipv6_only)?;
    
    // Apply exclude subnets if specified
    if let Some(exclude_subnets) = opts.exclude_subnets {
        for exclude_net_str in exclude_subnets {
            let exclude_net = Ipv4Net::from_str(&exclude_net_str)?;
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

fn update_progress(position: u64, file_size: u64) -> Result<(), Box<dyn Error>> {
    let progress = (position as f64 / file_size as f64) * 100.0;
    print!("\rProgress: {:.2}%", progress);
    if position == file_size {
        println!();
    }
    io::stdout().flush().unwrap();
    Ok(())
}

fn scan_prefixes(
    file: &mut File,
    origin_asns: &HashSet<u32>,
    ipv4_only: bool,
    ipv6_only: bool
) -> Result<Vec<Ipv4Net>, Box<dyn Error>> {
    
    let file_size = file.metadata()?.len();
    let mut reader = BufReader::new(file.try_clone()?);
    let mut parser = BgpkitParser::from_reader(&mut reader);
    let mut status_interval = 10;

    match (ipv4_only, ipv6_only) {
        (true, false) => {
            parser = parser.add_filter("ip_version", "ipv4").expect("Failed to add IPv4 filter");
        }
        (false, true) => {
            parser = parser.add_filter("ip_version", "ipv6").expect("Failed to add IPv6 filter");
        }
        _ => {}
    }

    let mut prefixes = HashSet::new();
    for elem in parser.into_elem_iter() {
        status_interval += 1;
        if status_interval >= 10 {
            let position = file.seek(SeekFrom::Current(0))?;
            update_progress(position, file_size)?;
            status_interval = 0;
        }

        if !origin_asns.is_empty() {
            if let Some(elem_origin_asns) = &elem.origin_asns {
                if !elem_origin_asns.iter().any(|asn| origin_asns.contains(&asn.to_u32())) {
                    continue;
                }
            } else {
                continue;
            }
        }

        if let Ok(prefix) = Ipv4Net::from_str(&elem.prefix.to_string()) {
            prefixes.insert(prefix);
        }
    }

    update_progress(file_size, file_size)?;
    Ok(prefixes.iter().cloned().collect())
}

fn discover_associated_asns(file: &mut File, origin_asns: &HashSet<u32>) -> Result<HashSet<u32>, Box<dyn Error>> {
    let mut discovered_asns = HashSet::new();
    let mut observed_prefixes = HashSet::new();
    let reader = BufReader::new(file.try_clone()?);    
    let parser = BgpkitParser::from_reader(reader);
    let file_size = file.metadata()?.len();
    let mut status_interval = 10;

    for elem in parser.into_elem_iter() {
        status_interval += 1;
        if status_interval >= 10 {
            let position = file.seek(SeekFrom::Current(0))?;
            update_progress(position, file_size)?;
            status_interval = 0;
        }

        let prefix = Ipv4Net::from_str(&elem.prefix.to_string()).expect("Invalid prefix");
        observed_prefixes.insert(prefix);

        if let Some(elem_origin_asns) = &elem.origin_asns {
            for asn in elem_origin_asns {
                if origin_asns.contains(&asn.to_u32()) {
                    continue;
                }

                if prefix_overlaps(&prefix, &observed_prefixes) {
                    discovered_asns.insert(asn.to_u32());
                    break;
                }
            }
        }
    }

    update_progress(file_size, file_size)?;

    Ok(discovered_asns)
}

fn prefix_overlaps(prefix: &Ipv4Net, observed_prefixes: &HashSet<Ipv4Net>) -> bool {
    observed_prefixes.iter().any(|observed_prefix| {
        observed_prefix.contains(&prefix.network()) || prefix.contains(&observed_prefix.network())
    })
}

fn exclude_subnet(net: Ipv4Net, excluded_net: Ipv4Net) -> Vec<Ipv4Net> {
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

    // If net contains excluded_net, we need to split net into subnets
    // Generate subnets by splitting the net
    let left_subnet = Ipv4Net::new(net.network(), net.prefix_len() + 1).unwrap();
    let right_subnet = Ipv4Net::new(left_subnet.broadcast().saturating_add(1).into(), net.prefix_len() + 1).unwrap();

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
