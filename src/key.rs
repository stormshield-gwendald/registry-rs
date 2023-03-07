use std::{
    convert::{Infallible, TryInto},
    fmt::Display,
    io,
};

use utfx::{U16CStr, U16CString};
use windows::core::HSTRING;
use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::System::Registry::{HKEY, REG_NO_COMPRESSION, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegOpenCurrentUser, RegOpenKeyExW, RegSaveKeyExW};

use crate::iter;
use crate::{value, Hive};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Provided path not found: {0:?}")]
    NotFound(String, #[source] io::Error),

    #[error("Permission denied for given path: {0:?}")]
    PermissionDenied(String, #[source] io::Error),

    #[error("Invalid null found in provided path")]
    InvalidNul(#[from] utfx::NulError<u16>),

    #[error("An unknown IO error occurred for given path: {0:?}")]
    Unknown(String, #[source] io::Error),

    #[error("Windows error : {0}")]
    WindowsError(#[from] windows::core::Error),
}

impl Error {
    #[cfg(test)]
    pub(crate) fn is_not_found(&self) -> bool {
        match self {
            Error::NotFound(_, _) => true,
            _ => false,
        }
    }

    fn from_code(code: i32, value_name: String) -> Self {
        let err = io::Error::from_raw_os_error(code);

        return match err.kind() {
            io::ErrorKind::NotFound => Error::NotFound(value_name, err),
            io::ErrorKind::PermissionDenied => Error::PermissionDenied(value_name, err),
            _ => Error::Unknown(value_name, err),
        };
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unsafe { std::hint::unreachable_unchecked() }
    }
}

/// The safe representation of a Windows registry key.
#[derive(Debug)]
pub struct RegKey {
    pub(crate) hive: Hive,
    pub(crate) handle: HKEY,
    pub(crate) path: U16CString,
}

impl Display for RegKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.hive)?;
        let path = self.path.to_string_lossy();

        if path != "" {
            f.write_str(r"\")?;
            f.write_str(&path)?;
        }

        Ok(())
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        // No point checking the return value here.
        unsafe { RegCloseKey(self.handle) };
    }
}

impl RegKey {
    #[inline]
    pub fn open<P>(&self, path: P, sec: REG_SAM_FLAGS) -> Result<RegKey, Error>
    where
        P: TryInto<U16CString>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        open_hkey(self.handle, &path, sec).map(|handle| {
            let joined_path = format!(
                r"{}\{}",
                self.path.to_string().unwrap(),
                path.to_string().unwrap()
            );
            RegKey {
                hive: self.hive,
                handle,
                path: joined_path.try_into().unwrap(),
            }
        })
    }

    #[inline]
    pub fn write<P>(&self, file_path: P) -> Result<(), Error>
    where
        P: TryInto<U16CString>,
        P::Error: Into<Error>,
    {
        let path = file_path.try_into().map_err(Into::into)?;
        save_hkey(self.handle, &path)
    }

    #[inline]
    pub fn create<P>(&self, path: P, sec: REG_SAM_FLAGS) -> Result<RegKey, Error>
    where
        P: TryInto<U16CString>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        create_hkey(self.handle, &path, sec).map(|handle| {
            let joined_path = format!(
                r"{}\{}",
                self.path.to_string().unwrap(),
                path.to_string().unwrap()
            );
            RegKey {
                hive: self.hive,
                handle,
                path: joined_path.try_into().unwrap(),
            }
        })
    }

    #[inline]
    pub fn delete<P>(&self, path: P, is_recursive: bool) -> Result<(), Error>
    where
        P: TryInto<U16CString>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        delete_hkey(self.handle, path, is_recursive)
    }

    #[inline]
    pub fn delete_self(self, is_recursive: bool) -> Result<(), Error> {
        delete_hkey(self.handle, U16CString::default(), is_recursive)
    }

    #[inline]
    pub fn value<S>(&self, value_name: S) -> Result<value::Data, value::Error>
    where
        S: TryInto<U16CString>,
        S::Error: Into<value::Error>,
    {
        value::query_value(self.handle, value_name)
    }

    #[inline]
    pub fn delete_value<S>(&self, value_name: S) -> Result<(), value::Error>
    where
        S: TryInto<U16CString>,
        S::Error: Into<value::Error>,
    {
        value::delete_value(self.handle, value_name)
    }

    #[inline]
    pub fn set_value<S>(&self, value_name: S, data: &value::Data) -> Result<(), value::Error>
    where
        S: TryInto<U16CString>,
        S::Error: Into<value::Error>,
    {
        value::set_value(self.handle, value_name, data)
    }

    #[inline]
    pub fn keys(&self) -> iter::Keys<'_> {
        match iter::Keys::new(self) {
            Ok(v) => v,
            Err(e) => unreachable!("{}", e),
        }
    }

    #[inline]
    pub fn values(&self) -> iter::Values<'_> {
        match iter::Values::new(self) {
            Ok(v) => v,
            Err(e) => unreachable!("{}", e),
        }
    }

    pub fn open_current_user(sec: REG_SAM_FLAGS) -> Result<RegKey, Error> {
        let mut hkey = HKEY::default();

        let result = unsafe { RegOpenCurrentUser(sec.0, &mut hkey) };

        if result == NO_ERROR {
            // TODO: use NT API to query path
            return Ok(RegKey {
                hive: Hive::CurrentUser,
                handle: hkey,
                path: "".try_into().unwrap(),
            });
        }

        let path = "<current user>".to_string();
        Err(Error::from_code(result.0 as i32, path))
    }
}

#[inline]
pub(crate) fn open_hkey<'a, P>(base: HKEY, path: P, sec: REG_SAM_FLAGS) -> Result<HKEY, Error>
where
    P: AsRef<U16CStr>,
{
    let path = HSTRING::from_wide(path.as_ref().as_slice())?;
    let mut hkey = HKEY::default();
    let result = unsafe { RegOpenKeyExW(base, &path, 0, sec, &mut hkey) };

    if result == NO_ERROR {
        return Ok(hkey);
    }

    let path = path.to_string_lossy();
    Err(Error::from_code(result.0 as i32, path))
}

#[inline]
pub(crate) fn save_hkey<'a, P>(hkey: HKEY, path: P) -> Result<(), Error>
where
    P: AsRef<U16CStr>,
{
    let path = HSTRING::from_wide(path.as_ref().as_slice())?;
    let result = unsafe { RegSaveKeyExW(hkey, &path, None, REG_NO_COMPRESSION) };

    if result == NO_ERROR {
        return Ok(());
    }

    let path = path.to_string_lossy();
    Err(Error::from_code(result.0 as i32, path))
}

#[inline]
pub(crate) fn delete_hkey<P>(base: HKEY, path: P, is_recursive: bool) -> Result<(), Error>
where
    P: AsRef<U16CStr>,
{
    let path = HSTRING::from_wide(path.as_ref().as_slice())?;

    let result = if is_recursive {
        unsafe { RegDeleteTreeW(base, &path) }
    } else {
        unsafe { RegDeleteKeyW(base, &path) }
    };

    if result == NO_ERROR {
        return Ok(());
    }

    let path = path.to_string_lossy();
    Err(Error::from_code(result.0 as i32, path))
}

#[inline]
pub(crate) fn create_hkey<P>(base: HKEY, path: P, sec: REG_SAM_FLAGS) -> Result<HKEY, Error>
where
    P: AsRef<U16CStr>,
{
    let path = HSTRING::from_wide(path.as_ref().as_slice())?;

    let mut hkey = HKEY::default();
    let result = unsafe {
        RegCreateKeyExW(
            base,
            &path,
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            sec,
            None,
            &mut hkey,
            None,
        )
    };

    if result == NO_ERROR {
        return Ok(hkey);
    }

    let path = path.to_string_lossy();
    Err(Error::from_code(result.0 as i32, path))
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::Registry::KEY_READ;
    use crate::Hive;

    #[test]
    fn test_paths() {
        let key = Hive::CurrentUser
            .open("SOFTWARE\\Microsoft", KEY_READ)
            .unwrap();
        assert_eq!(key.to_string(), "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft")
    }

    #[test]
    fn non_existent_path() {
        let key_err = Hive::CurrentUser
            .open(
                r"2f773499-0946-4f83-9cad-4c8ebbaf9f73\050b26e8-ccac-4d2a-8d94-c597fc7ebf07",
                KEY_READ,
            )
            .unwrap_err();

        assert!(key_err.is_not_found());
    }

    #[test]
    fn non_existent_value() {
        let key = Hive::CurrentUser
            .open("SOFTWARE\\Microsoft", KEY_READ)
            .unwrap();
        let value_err = key
            .value("4e996ef6-a4ef-4026-b9fc-464d352d35ee")
            .unwrap_err();

        assert!(value_err.is_not_found());
    }
}
