use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use darqual_core::{ContactCard, Identity, Lockbox};

#[derive(Parser)]
#[command(
    name = "darqual",
    version = "0.0.1",
    about = "Darqual — anonymous encrypted messenger"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new identity and save to ~/.darqual/identity.toml
    Keygen {
        /// Overwrite an existing identity
        #[arg(long)]
        force: bool,
    },
    /// Print your Darqual address and contact card
    Address,
    /// Seal a message to a recipient contact card
    Seal {
        /// Recipient contact card string (dqcard1...)
        #[arg(long)]
        to: String,
        /// Plaintext message to seal
        #[arg(long)]
        message: String,
    },
    /// Open a lockbox with your stored identity
    Open {
        /// Lockbox envelope string (dqbox1...)
        #[arg(long)]
        lockbox: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen { force } => cmd_keygen(force),
        Command::Address => cmd_address(),
        Command::Seal { to, message } => cmd_seal(&to, &message),
        Command::Open { lockbox } => cmd_open(&lockbox),
    }
}

fn cmd_keygen(force: bool) -> Result<()> {
    let path = Identity::default_path().context("could not determine identity path")?;

    // If --force, remove the existing file so `save` can proceed.
    if path.exists() && force {
        std::fs::remove_file(&path).context("failed to remove existing identity")?;
    }

    let id = Identity::generate();
    // `save` now returns `Error::IdentityExists` if the file already exists (no --force).
    id.save(&path).context("failed to save identity")?;

    println!("✓ Identity generated");
    println!("  Path:    {}", path.display());
    println!("  Address: {}", id.address());
    println!();
    println!("Contact card (share this out-of-band):");
    println!("  {}", id.contact_card());

    Ok(())
}

fn cmd_address() -> Result<()> {
    let path = Identity::default_path().context("could not determine identity path")?;
    let id =
        Identity::load(&path).context("failed to load identity — run `darqual keygen` first")?;

    println!("Address: {}", id.address());
    println!();
    println!("Contact card:");
    println!("  {}", id.contact_card());

    Ok(())
}

fn cmd_seal(to: &str, message: &str) -> Result<()> {
    let card = to.parse::<ContactCard>().context("invalid contact card")?;

    if !card.verify() {
        anyhow::bail!("Contact card failed self-authentication check — address/pubkey mismatch");
    }

    let lb = Lockbox::seal_to_card(&card, message.as_bytes()).context("seal failed")?;

    println!("{}", lb.envelope);

    Ok(())
}

fn cmd_open(lockbox: &str) -> Result<()> {
    let path = Identity::default_path().context("could not determine identity path")?;
    let id =
        Identity::load(&path).context("failed to load identity — run `darqual keygen` first")?;

    match Lockbox::open(&id, lockbox) {
        Ok(plaintext) => {
            let msg = String::from_utf8_lossy(&plaintext);
            println!("{}", msg);
        }
        Err(darqual_core::Error::Decrypt) => {
            eprintln!("not addressed to you");
            std::process::exit(1);
        }
        Err(e) => {
            return Err(anyhow::anyhow!("failed to open lockbox: {}", e));
        }
    }

    Ok(())
}
