//! (Beta) `wrapped_secrets` provides Shamir's secret sharing with a wrapped secret. It currently offers versioning and MIME information about the data.

use crate::errors::*;
use crate::proto::wrapped::SecretProto;

use rand::Rng;

mod scheme;
pub(crate) use self::scheme::*;

/// Performs threshold k-out-of-n Shamir's secret sharing.
///
/// Uses a `rand::rngs::OsRng` as a source of entropy.
///
/// # Examples
///
/// ```
/// use etospheres_labs_rusty_secrets::wrapped_secrets::split_secret;
///
/// let secret = "These programs were never about terrorism: they’re about economic spying, \
///               social control, and diplomatic manipulation. They’re about power.";
///
/// let result = split_secret(
///     7,
///     10,
///     &secret.as_bytes(),
///     Some("text/html".to_string()),
///     true,
/// );
///
/// match result {
///     Ok(shares) => {
///         // Do something with the shares
///     },
///     Err(_) => {
///         // Deal with error
///     }
/// }
/// ```
pub fn split_secret(
    k: u8,
    n: u8,
    secret: &[u8],
    mime_type: Option<String>,
    sign_shares: bool,
) -> Result<Vec<String>> {
    WrappedSecrets
        .split_secret(&mut rand::rng(), k, n, secret, mime_type, sign_shares)
        .map(|shares| shares.into_iter().map(Share::into_string).collect())
}

/// Performs threshold k-out-of-n Shamir's secret sharing with a custom RNG.
///
/// # Examples
///
/// ```
/// # extern crate etospheres_labs_rusty_secrets;
/// # extern crate rand_chacha;
/// #
/// # fn main() {
/// use etospheres_labs_rusty_secrets::wrapped_secrets::split_secret_rng;
/// use rand_chacha::ChaChaRng;
/// use rand_chacha::rand_core::SeedableRng;
///
/// let seed = [42u8; 32]; // REPLACE WITH PROPER SEED
/// let mut rng = ChaChaRng::from_seed(seed);
///
/// let secret = "These programs were never about terrorism: they’re about economic spying, \
///               social control, and diplomatic manipulation. They’re about power.";
///
/// let result = split_secret_rng(
///     &mut rng,
///     7,
///     10,
///     &secret.as_bytes(),
///     Some("text/html".to_string()),
///     true,
/// );
///
/// match result {
///     Ok(shares) => {
///         // Do something with the shares
///     },
///     Err(_) => {
///         // Deal with error
///     }
/// }
/// # }
/// ```
pub fn split_secret_rng<R: Rng>(
    rng: &mut R,
    k: u8,
    n: u8,
    secret: &[u8],
    mime_type: Option<String>,
    sign_shares: bool,
) -> Result<Vec<String>> {
    WrappedSecrets
        .split_secret(rng, k, n, secret, mime_type, sign_shares)
        .map(|shares| shares.into_iter().map(Share::into_string).collect())
}

/// Recovers the secret from a k-out-of-n Shamir's secret sharing.
///
/// At least `k` distinct shares need to be provided to recover the share.
///
/// # Examples
///
/// ```rust
/// use etospheres_labs_rusty_secrets::wrapped_secrets::recover_secret;
///
/// let share1 = "2-1-Cha7s14Q/mSwWko0ittr+/Uf79RHQMIP".to_string();
/// let share2 = "2-4-ChaydsUJDypD9ZWxwvIICh/cmZvzusOF".to_string();
/// let shares = vec![share1, share2];
///
/// match recover_secret(&shares, false) {
///     Ok(secret) => {
///         // Do something with the secret
///     },
///     Err(e) => {
///         // Deal with the error
///     }
/// }
/// ```
pub fn recover_secret(shares: &[String], verify_signatures: bool) -> Result<SecretProto> {
    let shares = Share::parse_all(shares, verify_signatures)?;
    WrappedSecrets::recover_secret(shares, verify_signatures)
}
