//! Optional Direct3D 12 Agility SDK activation.
//!
//! Windows 10's inbox D3D12 runtime tops out at Shader Model 6.5. On supported
//! Windows 10 builds, ID3D12SDKConfiguration1 can load an app-supplied Agility
//! SDK runtime without PE-level D3D12SDKVersion / D3D12SDKPath exports.
//!
//! Search order: VICTORY_D3D12_DIR (when set), <exe-dir>\D3D12, <exe-dir>,
//! then %LOCALAPPDATA%\victory\D3D12. If none is present, inbox D3D12 remains
//! available for older systems and for machines that do not need Agility.

use std::ffi::{CString, c_void};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL;
use windows::Win32::Graphics::Direct3D12::*;
use windows::core::{GUID, IUnknown, Interface, PCSTR, Param};

/// Environment variable overriding the Agility SDK directory.
pub const ENV: &str = "VICTORY_D3D12_DIR";

#[derive(Debug)]
pub enum State {
    Loaded {
        factory: ID3D12DeviceFactory,
        version: u32,
        dir: PathBuf,
    },
    NotFound,
    Unavailable(String),
}

static STATE: OnceLock<State> = OnceLock::new();

#[derive(Debug, PartialEq, Eq)]
enum Resolution {
    Found { dir: PathBuf, version: u32 },
    NotFound,
    Unavailable(String),
}

fn candidates(env_override: Option<PathBuf>, exe_dir: Option<PathBuf>, local_app_data: Option<PathBuf>) -> Vec<PathBuf> {
    if let Some(dir) = env_override.filter(|p| !p.as_os_str().is_empty()) {
        // An explicit override is authoritative: do not silently use a different SDK.
        return vec![dir];
    }
    let mut dirs = Vec::new();
    if let Some(dir) = exe_dir {
        dirs.push(dir.join("D3D12"));
        dirs.push(dir);
    }
    if let Some(dir) = local_app_data {
        dirs.push(dir.join("victory").join("D3D12"));
    }
    dirs
}

/// Read the Agility SDK version exported as data by D3D12Core.dll.
fn read_sdk_version(dir: &Path) -> Result<u32, String> {
    let dll = dir.join("D3D12Core.dll");
    let bytes = std::fs::read(&dll).map_err(|e| format!("{}: {e}", dll.display()))?;
    let pe = victory_pe::ImageInfo::parse(&bytes)
        .map_err(|e| format!("{}: invalid PE image: {e}", dll.display()))?;
    if !pe.is_dll() {
        return Err(format!("{}: not a DLL", dll.display()));
    }
    let rva = pe
        .exports
        .iter()
        .find_map(|export| {
            (export.name.as_deref() == Some("D3D12SDKVersion"))
                .then_some(export.rva)
                .flatten()
        })
        .ok_or_else(|| format!("{}: missing D3D12SDKVersion export", dll.display()))?;
    let offset = pe
        .rva_to_file_offset(rva)
        .ok_or_else(|| format!("{}: D3D12SDKVersion RVA is not file-backed", dll.display()))? as usize;
    let raw = bytes
        .get(offset..offset.checked_add(4).ok_or("SDK version offset overflow")?)
        .ok_or_else(|| format!("{}: truncated D3D12SDKVersion export", dll.display()))?;
    let version = u32::from_le_bytes(raw.try_into().expect("four-byte slice"));
    if version == 0 {
        return Err(format!("{}: D3D12SDKVersion is zero", dll.display()));
    }
    Ok(version)
}

fn resolve_dir(
    env_override: Option<PathBuf>,
    exe_dir: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
) -> Resolution {
    let explicit = env_override.as_ref().is_some_and(|p| !p.as_os_str().is_empty());
    let dirs = candidates(env_override, exe_dir, local_app_data);
    let mut last_error = None;
    for dir in dirs {
        if !dir.join("D3D12Core.dll").is_file() {
            if explicit {
                return Resolution::Unavailable(format!(
                    "{ENV}={} has no D3D12Core.dll",
                    dir.display()
                ));
            }
            continue;
        }
        match read_sdk_version(&dir) {
            Ok(version) => return Resolution::Found { dir, version },
            Err(error) => {
                last_error = Some(error);
                if explicit {
                    break;
                }
            }
        }
    }
    match last_error {
        Some(error) => Resolution::Unavailable(error),
        None => Resolution::NotFound,
    }
}

fn clean_env_path(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let value = value?;
    if value.is_empty() {
        return None;
    }
    if let Some(text) = value.to_str() {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        return Some(PathBuf::from(text));
    }
    Some(PathBuf::from(value))
}

fn encode_wide_for_code_page(wide: &[u16], code_page: u32) -> Result<CString, String> {
    use windows_sys::Win32::Globalization::{
        CP_UTF8, WC_ERR_INVALID_CHARS, WC_NO_BEST_FIT_CHARS, WideCharToMultiByte,
    };

    if wide.is_empty() || wide.contains(&0) {
        return Err("invalid Agility SDK path".into());
    }
    let wide_len = i32::try_from(wide.len()).map_err(|_| "Agility SDK path is too long")?;
    let utf8_like = code_page == CP_UTF8 || code_page == 54936;
    let flags = if utf8_like { WC_ERR_INVALID_CHARS } else { WC_NO_BEST_FIT_CHARS };
    let mut used_default = 0i32;
    let used_ptr = if utf8_like { std::ptr::null_mut() } else { &mut used_default };
    // SAFETY: the first call only queries the output length for this valid UTF-16 slice.
    let needed = unsafe {
        WideCharToMultiByte(
            code_page,
            flags,
            wide.as_ptr(),
            wide_len,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            used_ptr,
        )
    };
    if needed <= 0 || used_default != 0 {
        return Err("could not encode Agility SDK path in the active code page".into());
    }
    let mut bytes = vec![0u8; needed as usize];
    used_default = 0;
    let used_ptr = if utf8_like { std::ptr::null_mut() } else { &mut used_default };
    // SAFETY: bytes has the exact output size returned by the sizing call.
    let written = unsafe {
        WideCharToMultiByte(
            code_page,
            flags,
            wide.as_ptr(),
            wide_len,
            bytes.as_mut_ptr(),
            needed,
            std::ptr::null(),
            used_ptr,
        )
    };
    if written <= 0 || used_default != 0 {
        return Err("Agility SDK path contains characters not representable by the active code page".into());
    }
    bytes.truncate(written as usize);
    CString::new(bytes).map_err(|_| "Agility SDK path contains an interior NUL".into())
}

fn format_sdk_path(dir: &Path) -> Result<CString, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Globalization::GetACP;

    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    if wide.is_empty() {
        return Err("empty Agility SDK directory".into());
    }
    if *wide.last().unwrap() == b'/' as u16 {
        *wide.last_mut().unwrap() = b'\\' as u16;
    } else if *wide.last().unwrap() != b'\\' as u16 {
        wide.push(b'\\' as u16);
    }
    // SAFETY: GetACP has no parameters and returns the active ANSI code page.
    let code_page = unsafe { GetACP() };
    encode_wide_for_code_page(&wide, code_page)
}

fn init() -> State {
    let env_dir = clean_env_path(std::env::var_os(ENV));
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let local_app_data = clean_env_path(std::env::var_os("LOCALAPPDATA"));
    let (dir, version) = match resolve_dir(env_dir, exe_dir, local_app_data) {
        Resolution::Found { dir, version } => (dir, version),
        Resolution::NotFound => return State::NotFound,
        Resolution::Unavailable(reason) => return State::Unavailable(reason),
    };
    let dir = match std::path::absolute(&dir) {
        Ok(path) => path,
        Err(error) => return State::Unavailable(format!("cannot make SDK path absolute: {error}")),
    };
    let sdk_path = match format_sdk_path(&dir) {
        Ok(path) => path,
        Err(error) => return State::Unavailable(error),
    };
    match create_factory(version, &dir, &sdk_path) {
        Ok(factory) => State::Loaded { factory, version, dir },
        Err(error) => State::Unavailable(error),
    }
}

type D3D12GetInterfaceFn = unsafe extern "system" fn(
    *const GUID,
    *const GUID,
    *mut *mut c_void,
) -> windows::core::HRESULT;

unsafe fn resolve_d3d12_get_interface() -> Result<D3D12GetInterfaceFn, String> {
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    let dll: Vec<u16> = "d3d12.dll".encode_utf16().chain(Some(0)).collect();
    // SAFETY: load the OS D3D12 loader explicitly from System32.
    let module = unsafe {
        LoadLibraryExW(dll.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32)
    };
    if module.is_null() {
        return Err("could not load System32\\d3d12.dll".into());
    }
    // SAFETY: module is a valid module handle and the symbol name is NUL-terminated.
    let symbol = unsafe { GetProcAddress(module, b"D3D12GetInterface\0".as_ptr()) }
        .ok_or_else(|| "D3D12GetInterface is unavailable (install Windows 10 22H2 KB5029331 or newer)".to_string())?;
    // SAFETY: D3D12GetInterface has the declared Windows ABI and signature.
    Ok(unsafe { std::mem::transmute::<_, D3D12GetInterfaceFn>(symbol) })
}

fn create_factory(
    version: u32,
    dir: &Path,
    sdk_path: &CString,
) -> Result<ID3D12DeviceFactory, String> {
    // SAFETY: the dynamically resolved function has D3D12GetInterface's ABI.
    unsafe {
        let get_interface = resolve_d3d12_get_interface()?;
        let mut raw: *mut c_void = std::ptr::null_mut();
        get_interface(
            &CLSID_D3D12SDKConfiguration,
            &ID3D12SDKConfiguration1::IID,
            &mut raw,
        )
        .ok()
        .map_err(|error| format!("ID3D12SDKConfiguration1 is unavailable: {error}"))?;
        if raw.is_null() {
            return Err("D3D12GetInterface returned a null SDK configuration".into());
        }
        let config = ID3D12SDKConfiguration1::from_raw(raw);
        let factory: ID3D12DeviceFactory = config
            .CreateDeviceFactory(version, PCSTR(sdk_path.as_ptr().cast()))
            .map_err(|error| format!("CreateDeviceFactory(v{version}, {}): {error}", dir.display()))?;
        factory
            .SetFlags(D3D12_DEVICE_FACTORY_FLAG_ALLOW_RETURNING_EXISTING_DEVICE)
            .map_err(|error| format!("ID3D12DeviceFactory::SetFlags: {error}"))?;
        // Essential: global D3D12 entry points (including
        // D3D12SerializeVersionedRootSignature) must dispatch through this SDK.
        factory
            .ApplyToGlobalState()
            .map_err(|error| format!("ID3D12DeviceFactory::ApplyToGlobalState: {error}"))?;
        Ok(factory)
    }
}

/// Initialize once, before any D3D12 free function or device is used.
pub fn state() -> &'static State {
    STATE.get_or_init(init)
}

pub fn create_device<P>(
    adapter: P,
    feature_level: D3D_FEATURE_LEVEL,
) -> windows::core::Result<ID3D12Device>
where
    P: Param<IUnknown>,
{
    let mut device: Option<ID3D12Device> = None;
    match state() {
        State::Loaded { factory, .. } => {
            // SAFETY: the factory outlives this call and device is a valid COM out-pointer.
            unsafe { factory.CreateDevice(adapter, feature_level, &mut device)? };
        }
        State::NotFound | State::Unavailable(_) => {
            // SAFETY: standard D3D12 device creation with a valid out-pointer.
            unsafe { D3D12CreateDevice(adapter, feature_level, &mut device)? };
        }
    }
    device.ok_or_else(windows::core::Error::empty)
}

pub fn configuration_interface<T: Interface>(
    class_id: &GUID,
) -> windows::core::Result<T> {
    match state() {
        State::Loaded { factory, .. } => {
            // SAFETY: factory is process-lifetime state; class_id is a valid D3D12 CLSID.
            unsafe { factory.GetConfigurationInterface::<T>(class_id) }
        }
        State::NotFound | State::Unavailable(_) => {
            let mut interface: Option<T> = None;
            // SAFETY: D3D12GetDebugInterface writes an owned COM interface on success.
            unsafe { D3D12GetDebugInterface(&mut interface)? };
            interface.ok_or_else(|| {
                windows::core::Error::from(windows::Win32::Foundation::E_NOINTERFACE)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_directory_is_the_only_candidate() {
        let paths = candidates(
            Some(PathBuf::from(r"E:\sdk")),
            Some(PathBuf::from(r"E:\app")),
            Some(PathBuf::from(r"C:\Users\tester\AppData\Local")),
        );
        assert_eq!(paths, [PathBuf::from(r"E:\sdk")]);
    }

    #[test]
    fn default_candidates_include_app_local_and_user_local_sdk_paths() {
        let paths = candidates(
            None,
            Some(PathBuf::from(r"E:\app")),
            Some(PathBuf::from(r"C:\Users\tester\AppData\Local")),
        );
        assert_eq!(
            paths,
            [
                PathBuf::from(r"E:\app\D3D12"),
                PathBuf::from(r"E:\app"),
                PathBuf::from(r"C:\Users\tester\AppData\Local\victory\D3D12"),
            ]
        );
    }
}
