use registry::Hive;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::{AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, SE_BACKUP_NAME, SE_RESTORE_NAME};
use windows::Win32::System::Registry::{KEY_READ, KEY_WRITE};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};


fn main() -> Result<(), std::io::Error> {
    let mut token = HANDLE::default();
    let r = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) };
    if !r.as_bool() {
        return Err(std::io::Error::last_os_error());
    }

    set_privilege(token, SE_RESTORE_NAME)?;
    set_privilege(token, SE_BACKUP_NAME)?;
    let hive_key = Hive::load_file(
        r"C:\Users\Default\NTUSER.DAT",
        KEY_READ | KEY_WRITE,
    )
    .unwrap();

    let keys: Vec<_> = hive_key.keys().map(|k| k.unwrap().to_string()).collect();

    println!("{:?}", keys);
    Ok(())
}

fn set_privilege(handle: HANDLE, name: PCWSTR) -> Result<(), std::io::Error> {
    let mut luid: LUID = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let r = unsafe { LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid) };
    if !r.as_bool() {
        return Err(std::io::Error::last_os_error());
    }

    let mut privilege = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    let r = unsafe {
        AdjustTokenPrivileges(
            handle,
            false,
            Some(&mut privilege),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
    };

    if !r.as_bool() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
