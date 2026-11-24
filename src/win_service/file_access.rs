//! Who may change, and who may read, a file or a folder - out of its owner and its access list.
//!
//! `--install` asks before it registers the service: the service reads its settings, its keys and
//! its exe from these folders, so whoever can write there decides what the service runs - with
//! the rights of the service, which a plain user must not get to.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, LookupAccountSidW, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSID, SID_NAME_USE,
};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// An entry which is only handed down to what is created inside, and gives nothing on the
/// folder itself.
const INHERIT_ONLY_ACE: u8 = 0x8;

const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;

/// Write data / add file, append / add folder, write extended attributes, delete child, write
/// attributes, delete, change the access list, take ownership.
const WRITE_RIGHTS: u32 =
    0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000 | GENERIC_WRITE | GENERIC_ALL;

/// Read data / list folder.
const READ_RIGHTS: u32 = 0x1 | GENERIC_READ | GENERIC_ALL;

/// Delete child, delete, change the access list, take ownership: what moves a folder away, or
/// one inside it - whatever the access list of what is moved says.
const MOVE_RIGHTS: u32 = 0x40 | DELETE | 0x4_0000 | 0x8_0000 | GENERIC_ALL;
const DELETE: u32 = 0x1_0000;

/// An account: its SID, and its name where Windows knows one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub sid: String,
    pub name: Option<String>,
}

impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name.as_deref() {
            Some(name) => write!(f, "{name} ({})", self.sid),
            None => f.write_str(self.sid.as_str()),
        }
    }
}

/// The owner and the entries of the access list which allow something on the object itself.
pub struct FileAccess {
    pub owner: Account,
    /// `None`: the object has no access list, which lets everybody do everything.
    pub allowed: Option<Vec<(Account, u32)>>,
}

/// What is wrong with the access to a file or a folder of the service.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Findings {
    /// Accounts which are not the system, the administrators or a service, and can change it.
    pub writers: Vec<String>,
    /// ... and can read it.
    pub readers: Vec<String>,
}

/// The system, the administrators, and the accounts of services (`NT SERVICE\...`, which only
/// an administrator makes - the service's own account and TrustedInstaller are of them).
fn is_trusted(sid: &str) -> bool {
    sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid.starts_with("S-1-5-80-")
}

impl FileAccess {
    pub fn findings(&self) -> Findings {
        let mut findings = Findings::default();

        // The owner changes the access list whatever it says.
        if !is_trusted(self.owner.sid.as_str()) {
            findings.writers.push(format!("{} as the owner", self.owner));
        }

        let Some(allowed) = self.allowed.as_ref() else {
            findings
                .writers
                .push("everybody: there is no access list".to_string());
            return findings;
        };

        for (account, rights) in allowed {
            if is_trusted(account.sid.as_str()) {
                continue;
            }

            let account = account.to_string();

            if rights & WRITE_RIGHTS != 0 {
                if !findings.writers.contains(&account) {
                    findings.writers.push(account);
                }
            } else if rights & READ_RIGHTS != 0 && !findings.readers.contains(&account) {
                findings.readers.push(account);
            }
        }

        findings
    }

    /// For a folder above the one of the service: the accounts - not the system, the
    /// administrators or a service - which can move it, or the folder inside it, away and put
    /// their own in its place. The access list of the folder of the service says nothing about
    /// that. Adding files here is not it: the root of a drive lets every user do so.
    ///
    /// `is_root`: the root of a drive is not moved, so the right to delete it means nothing.
    pub fn movers(&self, is_root: bool) -> Vec<String> {
        let mut movers = Vec::new();

        if !is_trusted(self.owner.sid.as_str()) {
            movers.push(format!("{} as the owner", self.owner));
        }

        let Some(allowed) = self.allowed.as_ref() else {
            movers.push("everybody: there is no access list".to_string());
            return movers;
        };

        let move_rights = if is_root {
            MOVE_RIGHTS & !DELETE
        } else {
            MOVE_RIGHTS
        };

        for (account, rights) in allowed {
            if is_trusted(account.sid.as_str()) || rights & move_rights == 0 {
                continue;
            }

            let account = account.to_string();
            if !movers.contains(&account) {
                movers.push(account);
            }
        }

        movers
    }
}

/// The owner and the access list of the file or folder at `path`.
pub fn read(path: &Path) -> Result<FileAccess, String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();

    // SAFETY: `wide` is a nul-terminated path; the out pointers are valid for the call, and what
    // they are given points into `descriptor`, which is freed below after its last use.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(format!(
            "the access list of {} can not be read: {}",
            path.display(),
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }

    // SAFETY: `owner` and `dacl` came from the call above and live as long as `descriptor`.
    let result = unsafe {
        FileAccess {
            owner: account(owner),
            allowed: (!dacl.is_null()).then(|| allowed_entries(dacl)),
        }
    };

    // SAFETY: `descriptor` was allocated by GetNamedSecurityInfoW, and nothing points into it
    // any more.
    unsafe { LocalFree(descriptor) };

    Ok(result)
}

/// SAFETY: `dacl` points to a valid access list.
unsafe fn allowed_entries(dacl: *mut ACL) -> Vec<(Account, u32)> {
    let mut result = Vec::new();

    for index in 0..(*dacl).AceCount as u32 {
        let mut ace = std::ptr::null_mut();
        if GetAce(dacl, index, &mut ace) == 0 {
            continue;
        }

        // Every kind of entry starts with the header; the allowed one is the header, the rights
        // and the SID.
        let ace = ace as *const ACCESS_ALLOWED_ACE;
        let header = (*ace).Header;

        if header.AceType != ACCESS_ALLOWED_ACE_TYPE || header.AceFlags & INHERIT_ONLY_ACE != 0 {
            continue;
        }

        let sid = std::ptr::addr_of!((*ace).SidStart) as PSID;
        result.push((account(sid), (*ace).Mask));
    }

    result
}

/// SAFETY: `sid` points to a valid SID.
unsafe fn account(sid: PSID) -> Account {
    let mut text: *mut u16 = std::ptr::null_mut();

    let sid_text = if ConvertSidToStringSidW(sid, &mut text) != 0 {
        let value = wide_to_string(text);
        LocalFree(text as _);
        value
    } else {
        "an account which can not be named".to_string()
    };

    let mut name = [0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain = [0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind: SID_NAME_USE = 0;

    let found = LookupAccountSidW(
        std::ptr::null(),
        sid,
        name.as_mut_ptr(),
        &mut name_len,
        domain.as_mut_ptr(),
        &mut domain_len,
        &mut kind,
    ) != 0;

    let name = found.then(|| {
        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
        if domain.is_empty() {
            name
        } else {
            format!(r"{domain}\{name}")
        }
    });

    Account {
        sid: sid_text,
        name,
    }
}

/// SAFETY: `text` points to a nul-terminated UTF-16 string.
unsafe fn wide_to_string(text: *const u16) -> String {
    let mut len = 0;
    while *text.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM: &str = "S-1-5-18";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const USERS: &str = "S-1-5-32-545";
    const AUTHENTICATED_USERS: &str = "S-1-5-11";
    const A_SERVICE: &str = "S-1-5-80-1-2-3-4-5";

    const FULL: u32 = 0x1F01FF;
    const MODIFY: u32 = 0x1301BF;
    const READ_AND_EXECUTE: u32 = 0x1200A9;

    fn account(sid: &str) -> Account {
        Account {
            sid: sid.to_string(),
            name: None,
        }
    }

    fn access(owner: &str, allowed: &[(&str, u32)]) -> FileAccess {
        FileAccess {
            owner: account(owner),
            allowed: Some(
                allowed
                    .iter()
                    .map(|(sid, rights)| (account(sid), *rights))
                    .collect(),
            ),
        }
    }

    #[test]
    fn the_system_the_administrators_and_services_may_write() {
        let findings = access(
            ADMINISTRATORS,
            &[(SYSTEM, FULL), (ADMINISTRATORS, FULL), (A_SERVICE, MODIFY)],
        )
        .findings();

        assert_eq!(findings, Findings::default());
    }

    #[test]
    fn a_plain_account_which_can_write_is_found() {
        let findings = access(
            ADMINISTRATORS,
            &[
                (SYSTEM, FULL),
                (AUTHENTICATED_USERS, MODIFY),
                (USERS, READ_AND_EXECUTE),
            ],
        )
        .findings();

        assert_eq!(findings.writers, vec![AUTHENTICATED_USERS.to_string()]);
        assert_eq!(findings.readers, vec![USERS.to_string()]);
    }

    #[test]
    fn a_plain_owner_is_a_writer() {
        let findings = access("S-1-5-21-1-2-3-1001", &[(SYSTEM, FULL)]).findings();

        assert_eq!(
            findings.writers,
            vec!["S-1-5-21-1-2-3-1001 as the owner".to_string()]
        );
    }

    #[test]
    fn no_access_list_is_everybody() {
        let findings = FileAccess {
            owner: account(ADMINISTRATORS),
            allowed: None,
        }
        .findings();

        assert_eq!(findings.writers.len(), 1);
    }

    #[test]
    fn a_plain_account_which_can_delete_a_folder_above_can_move_it() {
        let above = access(
            ADMINISTRATORS,
            &[
                (SYSTEM, FULL),
                (AUTHENTICATED_USERS, MODIFY),
                (USERS, READ_AND_EXECUTE),
            ],
        );

        assert_eq!(above.movers(false), vec![AUTHENTICATED_USERS.to_string()]);
        // Modify has no "delete child", and the root of a drive is not deleted itself.
        assert!(above.movers(true).is_empty());
    }

    #[test]
    fn adding_files_to_a_folder_above_moves_nothing() {
        // The root of the system drive: every user may add a folder to it.
        let root = access(
            A_SERVICE,
            &[(SYSTEM, FULL), (AUTHENTICATED_USERS, 0x4), (USERS, READ_AND_EXECUTE)],
        );

        assert!(root.movers(true).is_empty());
        assert!(root.movers(false).is_empty());
    }

    #[test]
    fn full_control_of_the_root_moves_what_is_in_it() {
        let root = access(ADMINISTRATORS, &[(USERS, FULL)]);

        assert_eq!(root.movers(true), vec![USERS.to_string()]);
    }

    #[test]
    fn a_plain_owner_of_a_folder_above_can_move_it() {
        let above = access("S-1-5-21-1-2-3-1001", &[(SYSTEM, FULL)]);

        assert_eq!(above.movers(false).len(), 1);
    }

    /// Nobody but the system and the administrators moves the folder of Windows, or what the
    /// root of its drive holds.
    #[test]
    fn the_windows_folder_and_its_drive_are_not_moved_by_plain_accounts() {
        let windows = std::env::var("SystemRoot").unwrap();
        let windows = Path::new(windows.as_str());

        let movers = read(windows).unwrap().movers(false);
        assert!(movers.is_empty(), "{movers:?}");

        let movers = read(windows.parent().unwrap()).unwrap().movers(true);
        assert!(movers.is_empty(), "{movers:?}");
    }

    /// The folder of Windows itself: the system, the administrators and TrustedInstaller write,
    /// everybody else reads.
    #[test]
    fn the_windows_folder_is_read_as_it_is() {
        let windows = std::env::var("SystemRoot").unwrap();
        let findings = read(Path::new(windows.as_str())).unwrap().findings();

        assert!(findings.writers.is_empty(), "{:?}", findings.writers);
        assert!(!findings.readers.is_empty());
    }

    #[test]
    fn a_path_which_is_not_there_is_an_error() {
        let Err(err) = read(Path::new(r"C:\no\such\folder")) else {
            panic!("the access list of a folder which is not there was read");
        };
        assert!(err.contains(r"C:\no\such\folder"), "{err}");
    }
}
