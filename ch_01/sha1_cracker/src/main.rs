use sha1::Digest;
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};

const SHA1_HEX_STRING_LENGTH: usize = 40;

/// SHA-1 Cracker Entrypoint
///
/// When invoked with a wordlist and a target hash, finds an input yielding the hash.
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Usage:");
        println!("sha1_cracker: <wordlist.txt> <sha1_hash>");
        return Ok(());
    }

    let target_hash = args[2].trim();
    if target_hash.len() != SHA1_HEX_STRING_LENGTH {
        return Err(format!(
            "Invalid length for sha-1 hash (expecting {}, found {})",
            SHA1_HEX_STRING_LENGTH,
            target_hash.len()
        )
        .into());
    }

    let wordlist_file = File::open(&args[1])?;
    let reader = BufReader::new(&wordlist_file);

    // Load the whole word list into memory
    let candidates = reader
        .lines()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    for cand in candidates {
        let cand_trimmed = cand.trim();
        let cand_hash = &hex::encode(sha1::Sha1::digest(cand_trimmed.as_bytes()));

        if cand_hash == target_hash {
            println!("Found password: {}", cand);
            return Ok(());
        }
    }

    print!("Password not found in wordlist");

    Ok(())
}