//! Protocol buffer definitions.

#[allow(missing_docs)]
pub mod wrapped {
    include!(concat!(env!("OUT_DIR"), "/wrapped.rs"));
}

#[cfg(feature = "dss")]
#[allow(missing_docs)]
pub mod dss {
    include!(concat!(env!("OUT_DIR"), "/dss.rs"));
}

#[allow(missing_docs)]
mod version {
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}

pub use self::version::VersionProto;
