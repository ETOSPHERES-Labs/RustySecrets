use super::{MetaData, Share};
use crate::dss::format::{format_share_protobuf, parse_share_protobuf};
use crate::dss::utils::{btreemap_to_hashmap, hashmap_to_btreemap};
use crate::errors::*;
use crate::proto::dss::{MetaDataProto, ShareProto};

pub(crate) fn share_to_string(share: Share) -> String {
    let proto = share_to_protobuf(share);
    format_share_protobuf(&proto)
}

pub(crate) fn share_from_string(raw: &str) -> Result<Share> {
    let proto = parse_share_protobuf(raw)?;

    let metadata_proto = proto.meta_data.map(metadata_from_proto);

    let i = proto.id as u8;
    let k = proto.threshold as u8;
    let n = proto.shares_count as u8;

    if k < 1 || i < 1 {
        bail! {
            ErrorKind::ShareParsingError(
                format!("Found illegal share info: threshold = {}, identifier = {}.", k, i),
            )
        }
    }

    if n < 1 || k > n || i > n {
        bail! {
            ErrorKind::ShareParsingError(
                format!("Found illegal share info: shares_count = {}, threshold = {}, identifier = {}.", n, k, i),
            )
        }
    }

    let share = Share {
        id: i,
        threshold: k,
        shares_count: n,
        data: proto.data,
        metadata: metadata_proto,
    };

    Ok(share)
}

pub(crate) fn share_to_protobuf(share: Share) -> ShareProto {
    ShareProto {
        id: share.id.into(),
        threshold: share.threshold.into(),
        shares_count: share.shares_count.into(),
        data: share.data,
        hash: Vec::new(),
        meta_data: share.metadata.map(metadata_to_proto),
    }
}

fn metadata_to_proto(meta_data: MetaData) -> MetaDataProto {
    MetaDataProto {
        tags: btreemap_to_hashmap(meta_data.tags),
    }
}

fn metadata_from_proto(proto: MetaDataProto) -> MetaData {
    MetaData {
        tags: hashmap_to_btreemap(proto.tags),
    }
}
