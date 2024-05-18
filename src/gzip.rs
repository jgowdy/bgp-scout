use std::fs::File;
use std::{fs, io};
use std::io::{BufReader, BufWriter, Write};
use flate2::read::GzDecoder;

pub fn decompress_gzip(input_file: &str, output_file: &str) -> io::Result<()> {
    // Open the gzip-compressed file
    let file_in = File::open(input_file)?;
    let buf_reader = BufReader::new(file_in);

    // Create a GzDecoder to handle the gzip decompression
    let mut decoder = GzDecoder::new(buf_reader);

    // Open the output file
    let output_file_tmp = output_file.to_owned() + ".tmp";
    let file_out = File::create(&output_file_tmp)?;
    let mut buf_writer = BufWriter::new(file_out);

    // Copy all decompressed bytes from the decoder to the output file
    io::copy(&mut decoder, &mut buf_writer)?;

    // Ensure all data is flushed to the output file
    buf_writer.flush()?;

    fs::rename(output_file_tmp, output_file)?;

    Ok(())
}