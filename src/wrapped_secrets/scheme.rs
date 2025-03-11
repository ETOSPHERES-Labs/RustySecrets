use crate::errors::*;
use crate::proto::wrapped::SecretProto;
use crate::proto::VersionProto;
use crate::sss::Sss;

use prost::Message;
use rand::Rng;

pub(crate) use crate::sss::Share;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WrappedSecrets;

impl WrappedSecrets {
    /// Performs threshold k-out-of-n Shamir's secret sharing.
    pub fn split_secret<R: Rng>(
        &self,
        rng: &mut R,
        k: u8,
        n: u8,
        secret: &[u8],
        mime_type: Option<String>,
        sign_shares: bool,
    ) -> Result<Vec<Share>> {
        let mut rusty_secret = SecretProto::default();
        rusty_secret.set_version(VersionProto::InitialRelease);
        rusty_secret.secret = secret.to_owned();

        if let Some(mt) = mime_type {
            rusty_secret.mime_type = mt;
        }

        let mut buf = Vec::with_capacity(rusty_secret.encoded_len());
        // Unwrap is safe, since we have reserved sufficient capacity in the vector.
        rusty_secret.encode(&mut buf).unwrap();

        Sss.split_secret(rng, k, n, buf.as_slice(), sign_shares)
    }

    /// Recovers the secret from a k-out-of-n Shamir's secret sharing.
    ///
    /// At least `k` distinct shares need to be provided to recover the share.
    pub fn recover_secret(shares: Vec<Share>, verify_signatures: bool) -> Result<SecretProto> {
        let secret = Sss::recover_secret(shares, verify_signatures)?;

        SecretProto::decode(secret.as_slice()).chain_err(|| ErrorKind::SecretDeserializationError)
    }
}
