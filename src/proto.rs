//! Protocol buffer definitions.

#[allow(missing_docs)]
pub mod wrapped {
    include!(concat!(env!("OUT_DIR"), "/proto/wrapped/mod.rs"));
    pub use self::secret::SecretProto;
    pub use self::share::ShareProto;
    use super::version;
}

#[cfg(feature = "dss")]
#[allow(missing_docs)]
pub mod dss {
    include!(concat!(env!("OUT_DIR"), "/proto/dss/mod.rs"));
    pub use self::metadata::MetaDataProto;
    pub use self::secret::SecretProto;
    pub use self::share::ShareProto;
    use super::version;
}

#[allow(missing_docs)]
mod version {
    include!(concat!(env!("OUT_DIR"), "/proto/version/mod.rs"));
    pub use self::version::VersionProto;
}

pub use self::version::VersionProto;
