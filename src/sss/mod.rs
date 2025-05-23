//! SSS provides Shamir's secret sharing with raw data.

use crate::errors::*;

mod share;
pub(crate) use self::share::*;

mod format;
// pub use self::format::*;

mod scheme;
pub(crate) use self::scheme::*;

mod encode;

use rand::Rng;
use ring::digest::{Algorithm, SHA512};

static HASH_ALGO: &Algorithm = &SHA512;

/// Performs threshold k-out-of-n Shamir's secret sharing.
///
/// Uses a `rand::rngs::OsRng` as a source of entropy.
///
/// # Examples
///
/// ```
/// use etospheres_labs_rusty_secrets::sss::split_secret;
///
/// let secret = "These programs were never about terrorism: they’re about economic spying, \
///               social control, and diplomatic manipulation. They’re about power.";
///
/// match split_secret(7, 10, &secret.as_bytes(), true) {
///     Ok(shares) => {
///         // Do something with the shares
///     },
///     Err(_) => {
///         // Deal with error
///     }
/// }
/// ```
pub fn split_secret(k: u8, n: u8, secret: &[u8], sign_shares: bool) -> Result<Vec<String>> {
    Sss.split_secret(&mut rand::rng(), k, n, secret, sign_shares)
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
/// # use rand_chacha::ChaChaRng;
/// # use rand_chacha::rand_core::SeedableRng;
/// #
/// # fn some_custom_rng() -> ChaChaRng {
/// #     let seed = [42u8; 32];
/// #     ChaChaRng::from_seed(seed)
/// # }
/// #
/// # fn main() {
/// use etospheres_labs_rusty_secrets::sss::split_secret_rng;
///
/// let secret = "These programs were never about terrorism: they’re about economic spying, \
///               social control, and diplomatic manipulation. They’re about power.";
///
/// let mut rng = some_custom_rng();
///
/// match split_secret_rng(&mut rng, 7, 10, &secret.as_bytes(), true) {
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
    sign_shares: bool,
) -> Result<Vec<String>> {
    Sss.split_secret(rng, k, n, secret, sign_shares)
        .map(|shares| shares.into_iter().map(Share::into_string).collect())
}

/// Recovers the secret from a k-out-of-n Shamir's secret sharing scheme.
///
/// At least `k` distinct shares need to be provided to recover the secret.
///
/// # Examples
///
/// ```
/// use etospheres_labs_rusty_secrets::sss::recover_secret;
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
pub fn recover_secret(shares: &[String], verify_signatures: bool) -> Result<Vec<u8>> {
    let shares = Share::parse_all(shares, verify_signatures)?;
    Sss::recover_secret(shares, verify_signatures)
}
