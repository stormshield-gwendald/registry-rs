#![cfg(windows)]
#![deny(rust_2018_idioms)]

//! # Registry
//!
//! A convenient crate for safely accessing and mutating the Windows Registry.
//!
//! ## Usage
//!
//! In general, you will want to access a key from a [`Hive`](enum.Hive.html). This crate automatically handles
//! the conversion of `String` and `str` into a UTF-16 string suitable for FFI usage.
//!
//! ```no_run
//! # use windows::Win32::System::Registry::KEY_READ;
//! use registry::{Hive};
//! let regkey = Hive::CurrentUser.open(r"some\nested\path", KEY_READ)?;
//! # Ok::<(), registry::Error>(())
//! ```
//!
//! A [`RegKey`](struct.RegKey.html) has all necessary functionality for querying subkeys, values within a key,
//! and accessing key value data.
//!
//! ```no_run
//! # use windows::Win32::System::Registry::KEY_READ;
//! use registry::{Data, Hive};
//! # let regkey = Hive::CurrentUser.open(r"some\nested\path", KEY_READ)?;
//! regkey.set_value("SomeValue", &Data::U32(42))?;
//! assert!(matches!(regkey.value("SomeValue")?, Data::U32(42)));
//! # Ok::<(), registry::Error>(())
//! ```
//!
//! [`RegKey`](struct.RegKey.html)s also support iteration of all subkeys with the `keys()` function, and all values with the `values()` function.
//!

mod hive;
pub mod iter;
pub mod key;
pub mod value;

pub use hive::Hive;
#[doc(inline)]
pub use key::RegKey;
#[doc(inline)]
pub use value::Data;

#[derive(Debug, thiserror::Error)]
/// A higher level convenience error type for functions that do
/// multiple registry-related operations and don't want to invent
/// their own error type.
pub enum Error {
    #[error("A key error occurred.")]
    Key(#[from] key::Error),
    #[error("A keys error occurred.")]
    Keys(#[from] iter::keys::Error),
    #[error("A value error occurred.")]
    Value(#[from] value::Error),
    #[error("A values error occurred.")]
    Values(#[from] iter::values::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use windows::Win32::System::Registry::{KEY_ALL_ACCESS, KEY_READ};

    #[test]
    fn open_key() {
        let result = Hive::CurrentUser
            .open(r"SOFTWARE\Microsoft", KEY_ALL_ACCESS)
            .unwrap();
        println!("{}", result);
    }

    #[test]
    fn iter_keys() {
        let regkey = Hive::CurrentUser
            .open(r"SOFTWARE\Microsoft", KEY_ALL_ACCESS)
            .unwrap();
        let results = regkey.keys().collect::<Result<Vec<_>, _>>().unwrap();
        println!("{:?}", &results);
    }

    #[test]
    fn iter_values() {
        let regkey = Hive::CurrentUser
            .open(r"Keyboard Layout\Preload", KEY_READ)
            .unwrap();
        let results = regkey.values().collect::<Result<Vec<_>, _>>().unwrap();
        println!("{:?}", &results);
    }

    #[test]
    fn display_repr() {
        const KEY_UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let regkey = Hive::LocalMachine
            .open(KEY_UNINSTALL, KEY_READ)
            .unwrap();

        assert_eq!(
            format!("{}", regkey),
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        );
    }

    #[test]
    fn set_value_and_delete() {
        let regkey = Hive::CurrentUser
            .create(r"Test\registry-rust-crate", KEY_ALL_ACCESS)
            .unwrap();
        regkey
            .set_value("test", &Data::String("Meow meow".try_into().unwrap()))
            .unwrap();
        regkey
            .set_value(
                "test2",
                &Data::MultiString(vec![
                    "Meow meow".try_into().unwrap(),
                    "Woop woop".try_into().unwrap(),
                ]),
            )
            .unwrap();
        regkey.set_value("nothing", &Data::None).unwrap();
        regkey
            .set_value("some binary", &Data::Binary(vec![1, 2, 3, 4, 255]))
            .unwrap();
        regkey.set_value("u32", &Data::U32(0x1234FEFE)).unwrap();
        regkey.set_value("u32be", &Data::U32BE(0x1234FEFE)).unwrap();
        regkey
            .set_value("u64", &Data::U64(0x1234FEFE_1234FEFE))
            .unwrap();

        let results = regkey.values().collect::<Result<Vec<_>, _>>().unwrap();
        println!("{:?}", &results);

        assert_eq!(
            format!("{}", regkey),
            r"HKEY_CURRENT_USER\Test\registry-rust-crate"
        );
        let subkey = regkey.create("subkey", KEY_ALL_ACCESS).unwrap();
        assert_eq!(
            format!("{}", subkey),
            r"HKEY_CURRENT_USER\Test\registry-rust-crate\subkey"
        );

        let subkey = regkey.open("subkey", KEY_ALL_ACCESS).unwrap();
        assert_eq!(
            format!("{}", subkey),
            r"HKEY_CURRENT_USER\Test\registry-rust-crate\subkey"
        );

        Hive::CurrentUser.delete("Test", true).unwrap();
    }
}
