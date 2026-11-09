use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::core::GUID;
use windows_sys::Win32::Security::WinTrust::*;
use windows_sys::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetFileVersionInfoSizeW, GetFileVersionInfoW, GetLogicalDrives, VerQueryValueW,
};
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

// подпись
pub fn is_signed(path: &Path) -> bool {
    unsafe {
        let w = wide(path.as_os_str());
        let mut fi: WINTRUST_FILE_INFO = std::mem::zeroed();
        fi.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        fi.pcwszFilePath = w.as_ptr();
        let mut data: WINTRUST_DATA = std::mem::zeroed();
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut fi;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
        let mut action = GUID {
            data1: 0x00AAC56B,
            data2: 0xCD44,
            data3: 0x11d0,
            data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
        };
        let hwnd = -1isize as *mut c_void;
        let r = WinVerifyTrust(hwnd, &mut action, &mut data as *mut _ as *mut c_void);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(hwnd, &mut action, &mut data as *mut _ as *mut c_void);
        r == 0 || is_catalog_signed(path)
    }
}

// подпись через каталог
fn is_catalog_signed(path: &Path) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Cryptography::Catalog::*;
    let Ok(file) = std::fs::File::open(path) else { return false };
    unsafe {
        let mut admin: isize = 0;
        if CryptCATAdminAcquireContext2(&mut admin, null(), windows_sys::core::w!("SHA256"), null(), 0) == 0 {
            return false;
        }
        let h = file.as_raw_handle() as *mut c_void;
        let mut len: u32 = 0;
        CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut len, null_mut(), 0);
        let mut ok = false;
        if len > 0 && len <= 128 {
            let mut hash = vec![0u8; len as usize];
            if CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut len, hash.as_mut_ptr(), 0) != 0 {
                let cat = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, null_mut());
                if cat != 0 {
                    let mut ci: CATALOG_INFO = std::mem::zeroed();
                    ci.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
                    if CryptCATCatalogInfoFromContext(cat, &mut ci, 0) != 0 {
                        let tag: String = hash.iter().map(|b| format!("{:02X}", b)).collect();
                        let wtag = wide(OsStr::new(&tag));
                        let wpath = wide(path.as_os_str());
                        let mut info: WINTRUST_CATALOG_INFO = std::mem::zeroed();
                        info.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
                        info.pcwszCatalogFilePath = ci.wszCatalogFile.as_ptr();
                        info.pcwszMemberTag = wtag.as_ptr();
                        info.pcwszMemberFilePath = wpath.as_ptr();
                        info.hCatAdmin = admin;
                        let mut data: WINTRUST_DATA = std::mem::zeroed();
                        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
                        data.dwUIChoice = WTD_UI_NONE;
                        data.fdwRevocationChecks = WTD_REVOKE_NONE;
                        data.dwUnionChoice = WTD_CHOICE_CATALOG;
                        data.Anonymous.pCatalog = &mut info;
                        data.dwStateAction = WTD_STATEACTION_VERIFY;
                        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
                        let mut action = GUID {
                            data1: 0x00AAC56B,
                            data2: 0xCD44,
                            data3: 0x11d0,
                            data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
                        };
                        let hwnd = -1isize as *mut c_void;
                        ok = WinVerifyTrust(hwnd, &mut action, &mut data as *mut _ as *mut c_void) == 0;
                        data.dwStateAction = WTD_STATEACTION_CLOSE;
                        WinVerifyTrust(hwnd, &mut action, &mut data as *mut _ as *mut c_void);
                    }
                    CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                }
            }
        }
        CryptCATAdminReleaseContext(admin, 0);
        ok
    }
}

// информация о файле
pub fn version_info(path: &Path) -> (String, String, String) {
    let empty = (String::new(), String::new(), String::new());
    unsafe {
        let w = wide(path.as_os_str());
        let size = GetFileVersionInfoSizeW(w.as_ptr(), null_mut());
        if size == 0 {
            return empty;
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(w.as_ptr(), 0, size, buf.as_mut_ptr() as *mut c_void) == 0 {
            return empty;
        }
        let query = |sub: &str| -> Option<(*mut c_void, u32)> {
            let s = wide(OsStr::new(sub));
            let mut p: *mut c_void = null_mut();
            let mut len: u32 = 0;
            if VerQueryValueW(buf.as_ptr() as *const c_void, s.as_ptr(), &mut p, &mut len) == 0
                || p.is_null()
                || len == 0
            {
                None
            } else {
                Some((p, len))
            }
        };
        let (tp, tl) = match query("\\VarFileInfo\\Translation") {
            Some(x) => x,
            None => return empty,
        };
        if tl < 4 {
            return empty;
        }
        let t = std::slice::from_raw_parts(tp as *const u16, 2);
        let base = format!("\\StringFileInfo\\{:04x}{:04x}\\", t[0], t[1]);
        let get = |name: &str| -> String {
            match query(&format!("{}{}", base, name)) {
                Some((p, len)) => {
                    let s = std::slice::from_raw_parts(p as *const u16, len as usize);
                    String::from_utf16_lossy(s).trim_end_matches('\0').trim().to_string()
                }
                None => String::new(),
            }
        };
        (get("CompanyName"), get("ProductName"), get("FileDescription"))
    }
}

// фоновый приоритет
pub fn set_background() {
    unsafe {
        let h = GetCurrentProcess();
        if SetPriorityClass(h, PROCESS_MODE_BACKGROUND_BEGIN) == 0 {
            SetPriorityClass(h, IDLE_PRIORITY_CLASS);
        }
    }
}

pub fn setup_console() {
    unsafe {
        SetConsoleOutputCP(65001);
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) != 0 {
            SetConsoleMode(h, mode | 0x0004);
        }
    }
}

// своя консоль
pub fn own_console() -> bool {
    unsafe {
        let mut buf = [0u32; 4];
        GetConsoleProcessList(buf.as_mut_ptr(), 4) <= 1
    }
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

pub fn fixed_drives() -> Vec<String> {
    let mut v = Vec::new();
    unsafe {
        let mask = GetLogicalDrives();
        for i in 0..26u32 {
            if mask & (1 << i) != 0 {
                let root = format!("{}:\\", (b'A' + i as u8) as char);
                let w = wide(OsStr::new(&root));
                if GetDriveTypeW(w.as_ptr()) == 3 {
                    v.push(root);
                }
            }
        }
    }
    let _ = null::<u8>();
    v
}

// TCP-соединения
pub fn tcp_conns() -> Vec<(u32, String, u16)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    let mut out = vec![];
    unsafe {
        let mut size = 0u32;
        GetExtendedTcpTable(null_mut(), &mut size, 0, 2, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize + 4096];
        let mut size2 = buf.len() as u32;
        if GetExtendedTcpTable(buf.as_mut_ptr() as *mut c_void, &mut size2, 0, 2, TCP_TABLE_OWNER_PID_ALL, 0) != 0 {
            return out;
        }
        let n = *(buf.as_ptr() as *const u32) as usize;
        let rows = buf.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
        for i in 0..n {
            let r = std::ptr::read_unaligned(rows.add(i));
            if r.dwState == 5 {
                let port = (((r.dwRemotePort & 0xFF) << 8) | ((r.dwRemotePort >> 8) & 0xFF)) as u16;
                let ip = r.dwRemoteAddr.to_le_bytes();
                out.push((r.dwOwningPid, format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port), port));
            }
        }
    }
    out
}

// язык системы
pub fn system_lang() -> crate::lang::Lang {
    use crate::lang::Lang;
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
    match unsafe { GetUserDefaultUILanguage() } & 0x3ff {
        0x19 | 0x23 | 0x3f => Lang::Ru,
        0x22 => Lang::Uk,
        0x07 => Lang::De,
        0x0a => Lang::Es,
        0x0c => Lang::Fr,
        0x16 => Lang::Pt,
        0x15 => Lang::Pl,
        0x1f => Lang::Tr,
        0x04 => Lang::Zh,
        _ => Lang::En,
    }
}
