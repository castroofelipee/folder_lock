use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use flate2::write::GzEncoder;
use flate2::Compression;
use rpassword::read_password;
use tar::Builder;

/// Command Line Interface
#[derive(Parser)]
#[command(name = "folder_lock_rs")]
#[command(about = "Packages (tar.gz) and encrypts a folder using a passphrase (age)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a folder into an .age file
    Encrypt {
        /// Folder to encrypt
        folder: PathBuf,
        /// Output encrypted file (.age)
        out: PathBuf,
    },
    /// Decrypt an .age file back into a folder
    Decrypt {
        /// Input encrypted file (.age)
        input: PathBuf,
        /// Output folder (must exist)
        out_folder: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { folder, out } => encrypt_folder(&folder, &out)?,
        Commands::Decrypt { input, out_folder } => decrypt_file(&input, &out_folder)?,
    }

    Ok(())
}

fn encrypt_folder(folder: &PathBuf, out: &PathBuf) -> Result<()> {
    if !folder.is_dir() {
        anyhow::bail!("'{}' is not a directory", folder.display());
    }

    println!("Enter passphrase (input hidden):");
    let pass = read_password().context("failed to read passphrase")?;
    if pass.is_empty() {
        anyhow::bail!("empty passphrase is not allowed");
    }

    // Create output file
    let fout = File::create(out)
        .with_context(|| format!("failed to create output file {}", out.display()))?;
    let mut w = BufWriter::new(fout);

    // Create age encryptor with passphrase
    // NOTE: The `age` crate provides helpers to create an encryptor that writes to a writer.
    // Here we use a passphrase-based encryptor which produces an encrypting writer.
    let encryptor = age::Encryptor::with_user_passphrase(pass.into_bytes());
    let mut age_writer = encryptor
        .wrap_output(&mut w)
        .context("failed to create age encrypting writer")?;

    // Create gzip encoder that writes into the age_writer,
    // then use a tar builder that writes into the gzip encoder.
    let gz = GzEncoder::new(&mut age_writer, Compression::default());
    let mut tar = Builder::new(gz);

    // Append folder contents into tar archive
    tar.append_dir_all(".", folder)
        .with_context(|| format!("failed to add '{}' to tar archive", folder.display()))?;

    // Finalize tar (which also flushes gzip data)
    tar.finish().context("failed to finalize tar archive")?;

    // Drop tar to ensure GzEncoder is flushed
    drop(tar);

    // Finalize the encryption writer
    age_writer
        .finish()
        .context("failed to finalize age writer")?;

    // Flush buffered output
    w.flush().context("failed to flush output buffer")?;

    println!("Encrypted '{}' → '{}'", folder.display(), out.display());
    Ok(())
}

fn decrypt_file(input: &PathBuf, out_folder: &PathBuf) -> Result<()> {
    if !out_folder.is_dir() {
        anyhow::bail!(
            "'{}' is not a directory (please create it first)",
            out_folder.display()
        );
    }

    println!("Enter passphrase (input hidden):");
    let pass = read_password().context("failed to read passphrase")?;
    if pass.is_empty() {
        anyhow::bail!("empty passphrase is not allowed");
    }

    // Open input file
    let fin = File::open(input)
        .with_context(|| format!("failed to open input file {}", input.display()))?;
    let mut r = BufReader::new(fin);

    // Create age decryptor
    let decryptor = age::Decryptor::new(&mut r)?;
    let mut plain_reader = match decryptor {
        age::Decryptor::Recipients(_) => {
            anyhow::bail!("file was encrypted for recipients (public key). This tool only supports passphrase-protected files.");
        }
        age::Decryptor::Passphrase(dec) => {
            let reader = dec.decrypt(&|_: &age::Recipient| Ok(pass.clone().into_bytes()))?;
            reader
        }
    };

    // The decrypted stream is a gzipped tar archive
    let mut gz = flate2::read::GzDecoder::new(&mut plain_reader);
    let mut archive = tar::Archive::new(&mut gz);
    archive
        .unpack(out_folder)
        .context("failed to unpack archive")?;

    println!(
        "Decrypted '{}' → '{}'",
        input.display(),
        out_folder.display()
    );
    Ok(())
}
