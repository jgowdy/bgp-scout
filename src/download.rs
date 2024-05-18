use std::error::Error;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Duration};
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use reqwest::header::{ETAG, HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use reqwest::StatusCode;
use filetime::FileTime;

#[allow(unused_imports)]
use log::{debug, info, warn, error};
use crate::gzip::decompress_gzip;

/// Downloads a file from the given URL and caches it.
///
/// # Arguments
///
/// * `url` - A string slice that holds the URL of the file to download.
/// * `output_file_name` - A string slice that holds the path to the output file.
/// * `verify_etag_interval` - The duration for which the cache is valid.
/// * `network_timeout` - An optional duration for the download timeout.
///
/// # Returns
///
/// * `Result<bool, Box<dyn Error>>` - Returns `Ok(true)` if the file was cached, `Ok(false)` if
///   the file was downloaded, or an `Err` with a boxed error if it failed.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// let result = download_cached("https://example.com/asset.gz", "/home/user/asset.gz", Duration::from_secs(86400), None);
/// assert!(result.is_ok());
/// ```
pub fn download_cached(url: &str, output_file_name: &Path, verify_etag_interval: Option<Duration>, network_timeout: Option<Duration>) -> Result<bool, Box<dyn Error>> {
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(86400);
    let verify_etag_duration = verify_etag_interval.unwrap_or(DEFAULT_TIMEOUT);
    let etag_file_name_str = format!("{}.etag", output_file_name.display());
    let etag_file_name = Path::new(&etag_file_name_str);
    let mut headers = HeaderMap::new();

    let mut delete_etag_file = false;
    let output_file_metadata_result = fs::metadata(output_file_name);
    // Does the output file already exist?
    if output_file_metadata_result.is_ok() {
        debug!("Output file {} exists", output_file_name.display());
        // Does the etag file exist?
        if let Ok(metadata) = fs::metadata(&etag_file_name) {
            debug!("etag file {} exists", etag_file_name.display());
            // Can we get the mtime of the etag file?
            if let Ok(modified) = metadata.modified() {
                // How long has it been since we've verified the etag with the server?
                let elapsed = modified.elapsed()?;
                debug!("etag file mtime elapsed is {} seconds", elapsed.as_secs());
                if elapsed > verify_etag_duration {
                    // We're going to verify etag with the server, get the etag value from the etag file
                    debug!("etag mtime is older than {} seconds, need to recheck with If-None-Match", verify_etag_duration.as_secs());
                    if let Ok(etag_file_str) = fs::read_to_string(&etag_file_name) {
                        if let Some(etag) = etag_file_str.lines().next().map(|line| line.trim()) {
                            if let Ok(etag_header_value) = HeaderValue::from_str(&etag) {
                                debug!("Adding If-None-Match header with etag value {}", etag);
                                headers.insert(IF_NONE_MATCH, etag_header_value);
                            } else {
                                warn!("Etag value {} is not a valid header value", etag);
                                delete_etag_file = true;
                            }
                        } else {
                            warn!("Can't get first line of etag file [{}]", etag_file_str);

                            delete_etag_file = true;
                        }
                    } else {
                        // Handle can't read etag value?
                        warn!("Failed to read etag value from {}", etag_file_name.display());

                        delete_etag_file = true;
                    }
                } else {
                    // We have an etag file with recent enough mtime
                    // We aren't going to check with the server
                    debug!("Etag file mtime new enough (verify interval {} seconds) to skip checking server", verify_etag_duration.as_secs());
                    return Ok(true);
                }
            } else {
                // Handle can't get modified time of etag from metadata?
                delete_etag_file = true;
            }
        } else {
            // Handle etag file doesn't exist
            debug!("Etag file {} does not exist", etag_file_name.display());

            // If we have an output file but no etag, attempt to use If-Modified-Since
            let output_file_metadata = output_file_metadata_result.unwrap();

            if let Ok(output_file_modified) = output_file_metadata.modified() {
                // Convert SystemTime to DateTime<Utc>
                let datetime: DateTime<Utc> = output_file_modified.into();

                // Format the DateTime<Utc> to an RFC 2822 formatted string
                let output_file_modified_str = datetime.to_rfc2822();

                debug!("Adding header If-Modified-Since with value {}", output_file_modified_str);
                headers.insert(IF_MODIFIED_SINCE, HeaderValue::from_str(output_file_modified_str.as_str())?);
            } else {
                warn!("Unable to get modified time from output file metadata {:?}", output_file_metadata);
            }
        }
    } else {
        // Handle output file doesn't exist
        debug!("Output file {} does not exist", output_file_name.display());
        delete_etag_file = true;
    }

    if delete_etag_file {
        debug!("Deleting etag file {}", etag_file_name.display());
        let _ = fs::remove_file(&etag_file_name);
    }

    let client = Client::new();
    let mut response = client.get(url).headers(headers).timeout(network_timeout.unwrap_or(DEFAULT_TIMEOUT)).send().map_err(|e| {
        format!("Failed to send request: {}", e)
    })?;

    match response.status() {
        StatusCode::NOT_MODIFIED => {
            debug!("HTTP request returned StatusCode::NOT_MODIFIED");
            if etag_file_name.exists() {
                debug!("Update mtime for etag file {}", etag_file_name_str);
                // Touch the ETag file to update its modified date
                let file = OpenOptions::new().write(true).open(&etag_file_name)?;
                file.set_len(file.metadata()?.len())?;
            } else {
                // If the server provides an etag and the etag file does not exist, save the etag
                if let Some(etag) = response.headers().get(ETAG) {
                    let etag_str = etag.to_str().unwrap();
                    debug!("Creating missing etag file {} with value {}", etag_file_name_str, etag_str);
                    let mut file = OpenOptions::new().create(true).write(true).open(etag_file_name)?;
                    writeln!(file, "{}", etag_str)?;
                } else {
                    debug!("Etag file does not exist and server did not return an etag in Not Modified response");
                }
            }

            Ok(true)
        },
        StatusCode::OK => {
            debug!("HTTP request returned StatusCode::OK");
            let file = File::create(output_file_name)?;
            let mut writer = BufWriter::new(file);
            debug!("Writing response to {}", output_file_name.display());
            if let Err(e) = response.copy_to(&mut writer) {
                let _ = fs::remove_file(&etag_file_name);
                let _ = fs::remove_file(output_file_name); // Attempt to delete the output file if write fails
                return Err(format!("Failed to write content to file: {}", e).into());
            }

            // If the server provides a Last-Modified header, set the mtime of the output file to match
            if let Some(last_modified_value) = response.headers().get(reqwest::header::LAST_MODIFIED) {
                let last_modified_str = last_modified_value.to_str()?;
                let last_modified = DateTime::parse_from_rfc2822(last_modified_str)?.with_timezone(&Utc);

                let modified_time = FileTime::from_unix_time(
                    last_modified.timestamp(),
                    last_modified.timestamp_subsec_nanos() as u32,
                );

                // Set the modified time of the output file
                filetime::set_file_mtime(output_file_name, modified_time)?;
                debug!("Set mtime {} to match server Last-Modified: {}", output_file_name.display(), last_modified_str);
            } else {
                debug!("No Last-Modified header found.");
                // TODO: What should we set the file time to that ensures optimal behavior?
            }

            // If the server provides an etag, save the etag in an etag+touch file
            if let Some(etag) = response.headers().get(ETAG) {
                debug!("Writing etag to file {}", etag_file_name.display());
                if let Err(e) = fs::write(&etag_file_name, etag.to_str()?) {
                    let _ = fs::remove_file(&etag_file_name);
                    return Err(format!("Failed to write etag to file {}: {}", etag_file_name.display(), e).into());
                }
            } else {
                debug!("Server did not return an etag");
            }

            Ok(false)
        },
        _ => {
            let _ = fs::remove_file(output_file_name); // Delete the output file on any other failure
            let _ = fs::remove_file(etag_file_name);
            Err(format!("Failed to download file: HTTP {}", response.status()).into())
        }
    }
}

pub fn download_cached_gzip(url: &str, output_file_gzip: &str, output_file: &str, verify_etag_interval: Duration) -> Result<String, Box<dyn Error>> {
    let cache_result = download_cached(url, Path::new(output_file_gzip), Some(verify_etag_interval), None)?;

    let mut need_decompress_gzip = false;
    if !cache_result {
        debug!("Downloaded gzipped file {}", output_file_gzip);
        need_decompress_gzip = true;
    } else {
        debug!("Using cached gzipped file {}", output_file_gzip);
        if !fs::metadata(output_file).is_ok() {
            debug!("Output file {} does not exist", output_file);
            need_decompress_gzip = true;
        }
    }
    if need_decompress_gzip {
        debug!("Decompressing gzipped file {}", output_file_gzip);
        decompress_gzip(output_file_gzip, output_file)?;
    }

    debug!("Output file {}", output_file);
    Ok(output_file.to_string())
}