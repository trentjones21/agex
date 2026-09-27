use std::io::{Read, Write};
use std::iter;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::{ExposeSecret, SecretString};
use age::{Decryptor, Encryptor, IdentityFile, NoCallbacks};
use rustler::{Atom, Binary, Env, Error, NifResult, OwnedBinary};

mod atoms {
    rustler::atoms! { ok }
}

type Recipient = Box<dyn age::Recipient + Send>;
type Identity = Box<dyn age::Identity + Send + Sync>;

// age's localized messages wrap interpolated values in Unicode isolation marks.
fn fail<T>(reason: impl ToString) -> NifResult<T> {
    let reason: String = reason
        .to_string()
        .chars()
        .filter(|c| !matches!(c, '\u{2066}'..='\u{2069}'))
        .collect();
    Err(Error::Term(Box::new(reason)))
}

fn ok_binary<'a>(env: Env<'a>, bytes: &[u8]) -> NifResult<(Atom, Binary<'a>)> {
    let mut bin = OwnedBinary::new(bytes.len()).ok_or(Error::RaiseAtom("enomem"))?;
    bin.as_mut_slice().copy_from_slice(bytes);
    Ok((atoms::ok(), bin.release(env)))
}

fn parse_recipient(s: &str) -> NifResult<Recipient> {
    let s = s.trim();
    if let Ok(r) = s.parse::<age::x25519::Recipient>() {
        return Ok(Box::new(r));
    }
    if let Ok(r) = s.parse::<age::ssh::Recipient>() {
        return Ok(Box::new(r));
    }
    fail(format!("invalid recipient: {s}"))
}

fn parse_ssh_identity(entry: &str) -> NifResult<Identity> {
    match age::ssh::Identity::from_buffer(entry.as_bytes(), None) {
        Ok(identity @ age::ssh::Identity::Unencrypted(_)) => Ok(Box::new(identity)),
        Ok(age::ssh::Identity::Encrypted(_)) => {
            fail("passphrase-protected SSH keys are not supported")
        }
        Ok(age::ssh::Identity::Unsupported(_)) => fail("unsupported SSH key type"),
        Err(_) => fail("invalid identity"),
    }
}

// Each entry may be a single key, the contents of an identity file (several keys and
// comments), or an OpenSSH private key. Error messages must never echo the input,
// since it is secret key material.
fn parse_identities(entries: &[&str]) -> NifResult<Vec<Identity>> {
    let mut identities = Vec::new();
    for entry in entries {
        if entry.trim_start().starts_with("-----BEGIN") {
            identities.push(parse_ssh_identity(entry)?);
            continue;
        }
        let parsed = IdentityFile::from_buffer(entry.as_bytes())
            .and_then(|file| {
                file.with_callbacks(NoCallbacks)
                    .into_identities()
                    .map_err(std::io::Error::other)
            })
            .or_else(|_| fail("invalid identity"))?;
        if parsed.is_empty() {
            return fail("invalid identity");
        }
        identities.extend(parsed);
    }
    if identities.is_empty() {
        return fail("no identities provided");
    }
    Ok(identities)
}

fn check_work_factor(log_n: u8) -> NifResult<u8> {
    if (1..64).contains(&log_n) {
        Ok(log_n)
    } else {
        fail("work factor must be between 1 and 63")
    }
}

fn write_age(encryptor: Encryptor, plaintext: &[u8], armor: bool) -> NifResult<Vec<u8>> {
    let format = if armor {
        Format::AsciiArmor
    } else {
        Format::Binary
    };
    let result = (|| -> std::io::Result<Vec<u8>> {
        let output = ArmoredWriter::wrap_output(Vec::new(), format)?;
        let mut writer = encryptor.wrap_output(output)?;
        writer.write_all(plaintext)?;
        writer.finish()?.finish()
    })();
    result.or_else(fail)
}

fn read_age<'a>(
    ciphertext: &[u8],
    identities: impl Iterator<Item = &'a dyn age::Identity>,
) -> NifResult<Vec<u8>> {
    let decryptor = Decryptor::new(ArmoredReader::new(ciphertext)).or_else(fail)?;
    let mut reader = decryptor.decrypt(identities).or_else(fail)?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext).or_else(fail)?;
    Ok(plaintext)
}

#[rustler::nif]
fn generate_x25519() -> (String, String) {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    (identity.to_string().expose_secret().to_owned(), recipient)
}

#[rustler::nif]
fn x25519_to_recipient(identity: &str) -> NifResult<(Atom, String)> {
    match identity.trim().parse::<age::x25519::Identity>() {
        Ok(identity) => Ok((atoms::ok(), identity.to_public().to_string())),
        Err(_) => fail("invalid identity"),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn encrypt<'a>(
    env: Env<'a>,
    plaintext: Binary,
    recipients: Vec<&str>,
    armor: bool,
) -> NifResult<(Atom, Binary<'a>)> {
    let recipients = recipients
        .into_iter()
        .map(parse_recipient)
        .collect::<NifResult<Vec<_>>>()?;
    let encryptor =
        Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as _)).or_else(fail)?;
    ok_binary(env, &write_age(encryptor, plaintext.as_slice(), armor)?)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn decrypt<'a>(
    env: Env<'a>,
    ciphertext: Binary,
    identities: Vec<&str>,
) -> NifResult<(Atom, Binary<'a>)> {
    let identities = parse_identities(&identities)?;
    let plaintext = read_age(
        ciphertext.as_slice(),
        identities.iter().map(|i| i.as_ref() as _),
    )?;
    ok_binary(env, &plaintext)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn encrypt_passphrase<'a>(
    env: Env<'a>,
    plaintext: Binary,
    passphrase: String,
    armor: bool,
    work_factor: Option<u8>,
) -> NifResult<(Atom, Binary<'a>)> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase));
    if let Some(log_n) = work_factor {
        recipient.set_work_factor(check_work_factor(log_n)?);
    }
    let encryptor = Encryptor::with_recipients(iter::once(&recipient as _)).or_else(fail)?;
    ok_binary(env, &write_age(encryptor, plaintext.as_slice(), armor)?)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn decrypt_passphrase<'a>(
    env: Env<'a>,
    ciphertext: Binary,
    passphrase: String,
    max_work_factor: Option<u8>,
) -> NifResult<(Atom, Binary<'a>)> {
    let mut identity = age::scrypt::Identity::new(SecretString::from(passphrase));
    if let Some(log_n) = max_work_factor {
        identity.set_max_work_factor(check_work_factor(log_n)?);
    }
    let plaintext = read_age(ciphertext.as_slice(), iter::once(&identity as _))?;
    ok_binary(env, &plaintext)
}

rustler::init!("Elixir.ExAge.Native");
