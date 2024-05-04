// use winapi::um::winuser::MessageBoxA;
use winapi::{
    ctypes, shared::ntdef::UNICODE_STRING, um::winuser::{MessageBoxA, MessageBoxW}
};
// use winapi::um::winuser::*;
use winapi::um::memoryapi::VirtualAlloc;

pub fn StringToUnicodeStringStruct(s: &str) -> UNICODE_STRING{
    unsafe{
    let unicode_string_struct: UNICODE_STRING = std::mem::zeroed<UNICODE_STRING>();
    let length = s.len() *2 as u16; //2 because each character takes 2 bit
    let max_len = (s.len() *2 +1) as u16;
    let uni_str = s.encode_utf16().collect::<Vec<u16>>();

        let basePTR = VirtualAlloc(
            std::ptr::null(),
            unicode_string_struct.Length as usize,
            0x1000|0x2000, //Commit and Reserve
            0x40 //ReadWriteExec 

        );

        std::ptr::copy(uni_str.as_ptr(), basePTR, unicode_string_struct.Length);
        unicode_string_struct.Buffer = basePTR as *mut u16;
        return unicode_string_struct; 
    }
}

fn main() {
    let textA = "Hello from Rust's Windows API\0";
    let titleA = "Offensive Rust\0";
    unsafe {
        let res = MessageBoxA(
            std::ptr::null_mut(),
            textA.as_bytes().as_ptr() as *const i8,
            titleA.as_bytes().as_ptr() as *const i8,
            0,
        );

        let textW = "Hello from Rust's Windows API with wide characters\0".encode_utf16().collect::<Vec<u16>>();
        let titleW = "Offensive RustW\0".encode_utf16().collect::<Vec<u16>>();

        let res2 = MessageBoxW(
            std::ptr::null_mut(),
            textW.as_ptr(),
            titleW.as_ptr(),
            1,
        );
    }
}
