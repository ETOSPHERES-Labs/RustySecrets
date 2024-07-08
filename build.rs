use std::env;
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::num::Wrapping;
use std::path::Path;

use protoc_rust::Customize;

const POLY: u8 = 0x1D;

/// replicates the least significant bit to every other bit
#[inline]
fn mask(bit: u8) -> u8 {
    (Wrapping(0u8) - Wrapping(bit & 1)).0
}

/// multiplies a polynomial with x and returns the residual
/// of the polynomial division with POLY as divisor
#[inline]
fn xtimes(poly: u8) -> u8 {
    (poly << 1) ^ (mask(poly >> 7) & POLY)
}

struct Tables {
    exp: [u8; 256],
    log: [u8; 256],
}

#[allow(clippy::match_wild_err_arm)]
fn generate_tables(mut file: &File) {
    let mut tabs = Tables {
        exp: [0; 256],
        log: [0; 256],
    };

    let mut tmp = 1;
    for power in 0..255usize {
        tabs.exp[power] = tmp;
        tabs.log[tmp as usize] = power as u8;
        tmp = xtimes(tmp);
    }
    tabs.exp[255] = 1;

    match write!(file, "{}", tabs) {
        Ok(()) => {}
        Err(_) => panic!("Could not format the table. Aborting build."),
    };
}

fn farray(array: [u8; 256], f: &mut fmt::Formatter) -> fmt::Result {
    for (index, value) in array.iter().enumerate() {
        write!(f, "{}", value)?;
        if index != array.len() - 1 {
            write!(f, ",")?;
        }
    }
    Ok(())
}

impl fmt::Display for Tables {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Tables {{")?;
        write!(f, "    exp: [")?;
        farray(self.exp, f)?;
        writeln!(f, "],")?;
        write!(f, "    log: [")?;
        farray(self.log, f)?;
        writeln!(f, "]")?;
        write!(f, "}};")
    }
}

fn build_protobuf<'a>(out_dir: &'a str, input: &'a [&'a str], includes: &'a [&'a str]) {
    std::fs::create_dir_all(out_dir).unwrap();
    protoc_rust::Codegen::new()
        .out_dir(out_dir)
        .inputs(input)
        .includes(includes)
        .customize(Customize {
            gen_mod_rs: Some(true),
            ..Default::default()
        })
        .run()
        .unwrap_or_else(|_| panic!("protoc error: out_dir={out_dir}, input={input:?}"));
}

fn generate_gf256_table() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("nothinghardcoded.rs");

    let mut f = File::create(dest).unwrap();

    write!(
        f,
        "pub struct Tables {{ \
         pub exp: [u8; 256], \
         pub log: [u8; 256] \
         }} \
         \
         pub static TABLES: Tables = "
    )
    .unwrap();

    generate_tables(&f);
}

#[allow(unused_must_use)]
fn main() {
    generate_gf256_table();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("proto");

    build_protobuf(
        dest.join("version").as_path().to_str().unwrap(),
        &["protobuf/version.proto"],
        &[],
    );
    build_protobuf(
        dest.join("dss").as_path().to_str().unwrap(),
        &[
            "protobuf/dss/metadata.proto",
            "protobuf/dss/secret.proto",
            "protobuf/dss/share.proto",
        ],
        &["protobuf", "protobuf/dss"],
    );
    build_protobuf(
        dest.join("wrapped").as_path().to_str().unwrap(),
        &[
            "protobuf/wrapped/secret.proto",
            "protobuf/wrapped/share.proto",
        ],
        &["protobuf", "protobuf/dss"],
    );
}
