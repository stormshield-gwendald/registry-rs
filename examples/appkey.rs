use std::path::Path;
use windows::Win32::System::Registry::{KEY_READ, KEY_WRITE};

use registry::{Hive, RegKey};

fn main() -> Result<(), std::io::Error> {
    let hive_key = Hive::load_file(
        Path::new(r"C:\Users\Default\NTUSER.DAT"),
        KEY_READ | KEY_WRITE,
    )
    .unwrap();

    walk_keys(hive_key, 0);
    Ok(())
}

fn walk_keys(key: RegKey, tabstop: i32) {
    for _ in 0..tabstop {
        print!("\t");
    }
    println!("{}", key.to_string());

    for subkey in key.keys() {
        let subkey = subkey.unwrap().open(KEY_READ).unwrap();
        walk_keys(subkey, tabstop + 1);
    }
}
