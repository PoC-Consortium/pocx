// Copyright (c) 2025 Proof of Capacity Consortium
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

cfg_if! {
    if #[cfg(unix)] {
        use std::process::Command;
        use std::process;
        use std::os::unix::fs::OpenOptionsExt;
        use fs2::FileExt;

        const O_DIRECT: i32 = 0o0_040_000;

        pub fn open_r_using_direct_io<P: AsRef<Path>>(path: P) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .custom_flags(O_DIRECT)
                .open(path)
        }

        pub fn open_r<P: AsRef<Path>>(path: P) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .open(path)
        }

        pub fn open_rw_using_direct_io<P: AsRef<Path>>(path: P) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .custom_flags(O_DIRECT)
                .open(path)
        }

        pub fn open_rw<P: AsRef<Path>>(path: P) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
        }

        // On unix, get the device id from 'df' command
        fn get_device_id_unix(path: &str) -> String {
            let output = match Command::new("df")
                    .arg(path)
                    .output() {
                Ok(output) => output,
                Err(_) => return "/dev/disk0".to_string(), // Fallback on command failure
            };
                let source = match String::from_utf8(output.stdout) {
                Ok(s) => s,
                Err(_) => return "/dev/disk0".to_string(), // Fallback on UTF-8 error
            };
                let lines: Vec<&str> = source.split('\n').collect();
                if lines.len() < 2 {
                    return "/dev/disk0".to_string(); // Fallback for tests
                }
                let parts: Vec<&str> = lines[1].split(' ').collect();
                if parts.is_empty() {
                    return "/dev/disk0".to_string(); // Fallback for tests
                }
                parts[0].to_string()
            }

        // on macos, use df and 'diskutil info <device>' to get the Device Block Size line
        // and extract the size
        fn get_sector_size_macos(path: &str) -> u64 {
            let source = get_device_id_unix(path);
            let output = match Command::new("diskutil")
                .arg("info")
                .arg(source)
                .output() {
                Ok(output) => output,
                Err(_) => return 4096, // Fallback on command failure
            };
            let source = match String::from_utf8(output.stdout) {
                Ok(s) => s,
                Err(_) => return 4096, // Fallback on UTF-8 error
            };
            let mut sector_size: u64 = 0;
            for line in source.split('\n').collect::<Vec<&str>>() {
                if line.trim().starts_with("Device Block Size") {
                    // e.g. in reverse: "Bytes 512 Size Block Device"
                    let source = line.rsplit(' ').collect::<Vec<&str>>()[1];

                    sector_size = source.parse::<u64>().unwrap_or(4096);
                }
            }
            if sector_size == 0 {
                sector_size = 4096;
            }
            sector_size
        }

        // on unix, use df and lsblk to extract the device sector size
        fn get_sector_size_unix(path: &str) -> u64 {
            let source = get_device_id_unix(path);
            let output = Command::new("lsblk")
                .arg(source)
                .arg("-o")
                .arg("PHY-SeC")
                .output()
                .map(|output| output.stdout)
                .unwrap_or_default();

            let sector_size = String::from_utf8(output).unwrap_or_default();
            let lines: Vec<&str> = sector_size.split('\n').collect();
            let sector_size_str = lines.get(1).unwrap_or(&"4096").trim();

            sector_size_str.parse::<u64>().unwrap_or(4096)
        }

        pub fn get_sector_size(path: &str) -> u64 {
            if cfg!(target_os = "android") {
                4096
            } else if cfg!(target_os = "macos") {
                get_sector_size_macos(path)
            } else {
                get_sector_size_unix(path)
            }
        }

        pub fn preallocate(file: &Path, size_in_bytes: u64, use_direct_io: bool) {
            let file = if use_direct_io {
                open_rw_using_direct_io(file)
            } else {
                open_rw(file)
            };
            match file {
                Ok(file) => {
                    if let Err(errno) = file.allocate(size_in_bytes) {
                        println!("\n\nERROR: preallocation failed. {}\n", errno);
                        process::exit(1);
                    }
                }
                Err(e) => {
                    println!("\n\nERROR: failed to open file for preallocation. {}\n", e);
                    process::exit(1);
                }
            }
        }
    } else {
        use std::ffi::CString;
        use std::ptr::null_mut;
        use std::iter::once;
        use std::ffi::OsStr;
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::fs::OpenOptionsExt;
        use core::mem::size_of_val;
        use winapi::um::errhandlingapi::GetLastError;
        use winapi::um::fileapi::SetFileValidData;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{OpenProcessToken,GetCurrentProcess};
        use winapi::um::securitybaseapi::AdjustTokenPrivileges;
        use winapi::um::winbase::LookupPrivilegeValueW;
        use winapi::um::winnt::{LUID, TOKEN_ADJUST_PRIVILEGES,TOKEN_PRIVILEGES,LUID_AND_ATTRIBUTES,SE_PRIVILEGE_ENABLED,SE_MANAGE_VOLUME_NAME};

        const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
        const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
        const FILE_FLAG_RANDOM_ACCESS: u32 = 0x1000_0000;
        const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;

        pub fn open_r_using_direct_io<P: AsRef<Path>>(path: P) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_NO_BUFFERING)
                .open(path)
        }

        pub fn open_r<P: AsRef<Path>>(path: P) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_RANDOM_ACCESS)
                .open(path)
        }

        pub fn open_rw_using_direct_io<P: AsRef<Path>>(path: P) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .custom_flags(FILE_FLAG_NO_BUFFERING)
                .open(path)
        }

        pub fn open_rw<P: AsRef<Path>>(path: P) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(FILE_FLAG_WRITE_THROUGH)
                .open(path)
        }

        pub fn get_sector_size(path: &str) -> u64 {
            let path_encoded = Path::new(path);
            let parent_path = match path_encoded.parent().and_then(|p| p.to_str()) {
                Some(p) => p,
                None => return 4096, // Default sector size if path is invalid
            };
            let parent_path_encoded = match CString::new(parent_path) {
                Ok(c) => c,
                Err(_) => return 4096, // Default sector size if CString creation fails
            };
            let mut sectors_per_cluster  = 0u32;
            let mut bytes_per_sector  = 0u32;
            let mut number_of_free_cluster  = 0u32;
            let mut total_number_of_cluster  = 0u32;
            if unsafe {
                winapi::um::fileapi::GetDiskFreeSpaceA(
                    parent_path_encoded.as_ptr(),
                    &mut sectors_per_cluster,
                    &mut bytes_per_sector,
                    &mut number_of_free_cluster,
                    &mut total_number_of_cluster
                )
            } == 0  {
                return 4096; // Default sector size if Windows API call fails
            };
            u64::from(bytes_per_sector)
        }

        pub fn preallocate(file: &Path, size_in_bytes: u64, use_direct_io: bool) {
            let mut result = true;
            result &= obtain_priviledge();

            let file = if use_direct_io {
                open_rw_using_direct_io(file)
            } else {
                open_rw(file)
            };

            let file = match file {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("ERROR: failed to open file for preallocation: {}", e);
                    return;
                }
            };

            if let Err(e) = file.set_len(size_in_bytes) {
                eprintln!("ERROR: failed to set file length during preallocation: {}", e);
                return;
            }

            if result {
                let handle = file.as_raw_handle();
                unsafe {
                    if SetFileValidData(handle, size_in_bytes as i64) == 0 {
                        // SetFileValidData failed, but this is not critical for file preallocation
                        // The file length was already set successfully above
                        eprintln!("WARNING: SetFileValidData failed, but file preallocation completed");
                    }
                }
            }
        }

        pub fn obtain_priviledge() -> bool {
            let mut result = true;

            let privilege_encoded: Vec<u16> = OsStr::new(SE_MANAGE_VOLUME_NAME)
                .encode_wide()
                .chain(once(0))
                .collect();

            let luid = LUID{
                HighPart: 0i32,
                LowPart: 0u32

            };

            unsafe {
                let mut htoken = null_mut();
                let mut tp = TOKEN_PRIVILEGES{
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES{
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                    }]
                };

                let temp = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut htoken);
                 result &= temp == 1;

                let temp = LookupPrivilegeValueW(null_mut(), privilege_encoded.as_ptr(), &mut tp.Privileges[0].Luid);
                result &= temp == 1;

                let temp = AdjustTokenPrivileges(htoken, 0, &mut tp, size_of_val(&tp) as u32, null_mut(), null_mut());

                CloseHandle(htoken);
                result &= temp == 1;
                result &=
                    GetLastError() == 0u32
            }
            result
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;

    #[test]
    fn test_get_sector_size() {
        // this should be true for any platform where this test runs
        // but it doesn't exercise all platform variants
        let cwd = env::current_dir().expect("Should be able to get current directory in test");
        let test_string = cwd
            .into_os_string()
            .into_string()
            .expect("Should be able to convert path to string in test");
        assert_ne!(0, get_sector_size(&test_string));
    }
}
