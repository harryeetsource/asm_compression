use capstone::prelude::*;
use clap::{Arg, ArgMatches, Command};
use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap};
use std::fs::{read, write};
use std::path::Path;
use std::error::Error;
use bit_vec::BitVec;
extern crate winapi;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::raw::c_void;
use std::ptr;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::ntdef::HANDLE;
use winapi::um::fileapi::{CreateFileA, ReadFile, OPEN_EXISTING, SetFilePointer, INVALID_SET_FILE_POINTER};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{MapViewOfFile, VirtualAlloc};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
use winapi::um::winbase::{FILE_BEGIN};
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    GENERIC_READ, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SECTION_HEADER_Misc, IMAGE_NT_HEADERS
};
use winapi::um::winnt::{IMAGE_SCN_MEM_EXECUTE};
use winapi::um::winnt::IMAGE_FILE_HEADER;
use std::mem;
use std::mem::{size_of, transmute};
use std::fs;
use std::io;
use std::sync::Arc;
use std::fs::OpenOptions;
use std::io::{Write, SeekFrom, Seek};
use core::ptr::null_mut;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::io::ErrorKind;
fn detect_architecture_via_ffi(input: &str) -> Result<capstone::arch::x86::ArchMode, Box<dyn std::error::Error>> {
    // Convert the file path to a CString
    let file_name = CString::new(input)?;
    
    // Open the file for reading
    let handle: HANDLE = unsafe {
        CreateFileA(
            file_name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    
    if handle == ptr::null_mut() {
        return Err(Box::from("Could not open the file."));
    }
    
    // Read the IMAGE_DOS_HEADER to find the NT headers
    let mut dos_header = IMAGE_DOS_HEADER {
        e_magic: 0,
        e_cblp: 0,
        e_cp: 0,
        e_crlc: 0,
        e_cparhdr: 0,
        e_minalloc: 0,
        e_maxalloc: 0,
        e_ss: 0,
        e_sp: 0,
        e_csum: 0,
        e_ip: 0,
        e_cs: 0,
        e_lfarlc: 0,
        e_ovno: 0,
        e_res: [0; 4],
        e_oemid: 0,
        e_oeminfo: 0,
        e_res2: [0; 10],
        e_lfanew: 0,
    };
    
    let mut bytes_read: DWORD = 0;
    unsafe {
        ReadFile(
            handle,
            &mut dos_header as *mut IMAGE_DOS_HEADER as LPVOID,
            std::mem::size_of::<IMAGE_DOS_HEADER>() as DWORD,
            &mut bytes_read,
            ptr::null_mut(),
        );
    }
    
    // Check for a valid DOS header
    if dos_header.e_magic != 0x5A4D {
        unsafe {
            CloseHandle(handle);
        }
        return Err(Box::from("Invalid DOS header."));
    }
    
    // Move to the NT headers offset
    unsafe {
        SetFilePointer(handle, dos_header.e_lfanew, ptr::null_mut(), FILE_BEGIN);
    }
    
    // Read the NT headers signature
    let mut nt_signature: DWORD = 0;
    unsafe {
        ReadFile(
            handle,
            &mut nt_signature as *mut DWORD as LPVOID,
            std::mem::size_of::<DWORD>() as DWORD,
            &mut bytes_read,
            ptr::null_mut(),
        );
    }
    
    // Check for a valid NT signature
    if nt_signature != 0x00004550 {
        unsafe {
            CloseHandle(handle);
        }
        return Err(Box::from("Invalid NT header signature."));
    }
    
    // Read the FileHeader to identify if it's 32-bit or 64-bit
    let mut file_header = IMAGE_FILE_HEADER {
        Machine: 0,
        NumberOfSections: 0,
        TimeDateStamp: 0,
        PointerToSymbolTable: 0,
        NumberOfSymbols: 0,
        SizeOfOptionalHeader: 0,
        Characteristics: 0,
    };
    
    unsafe {
        ReadFile(
            handle,
            &mut file_header as *mut IMAGE_FILE_HEADER as LPVOID,
            std::mem::size_of::<IMAGE_FILE_HEADER>() as DWORD,
            &mut bytes_read,
            ptr::null_mut(),
        );
    }
    
    // Check if it's 32-bit or 64-bit by reading the OptionalHeader
    let arch_mode = if file_header.Machine == 0x8664 {
        capstone::arch::x86::ArchMode::Mode64
    } else {
        capstone::arch::x86::ArchMode::Mode32
    };
    
    // Close the file handle
    unsafe {
        CloseHandle(handle);
    }
    
    Ok(arch_mode)
}
struct SectionInfo {
    header: IMAGE_SECTION_HEADER,
    data: Vec<u8>,
}


fn extract_pe_sections(data: &[u8]) -> Result<(Vec<u8>, Vec<SectionInfo>), Box<dyn std::error::Error>> {
    // Ensure data is large enough to contain an IMAGE_DOS_HEADER
    if data.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err(Box::from("Data too short for IMAGE_DOS_HEADER"));
    }

    let dos_header = unsafe { &*(data.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != 0x5A4D { // 'MZ' magic number check
        return Err(Box::from("Invalid DOS header."));
    }

    let nt_headers_offset = dos_header.e_lfanew as usize;
    if data.len() < nt_headers_offset + std::mem::size_of::<IMAGE_NT_HEADERS>() {
        return Err(Box::from("Invalid NT headers offset."));
    }

    // Verify the 'PE\0\0' signature
    let nt_headers = unsafe { &*(data.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS) };
    if nt_headers.Signature != 0x00004550 {
        return Err(Box::from("Invalid PE signature."));
    }

    let file_header = &nt_headers.FileHeader;
    let optional_header_size = file_header.SizeOfOptionalHeader as usize;
    let section_headers_start = nt_headers_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + optional_header_size;

    let mut sections = Vec::new();

    for i in 0..file_header.NumberOfSections as usize {
        let section_header: &IMAGE_SECTION_HEADER = unsafe { &*(data.as_ptr().add(section_headers_start + i * std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const IMAGE_SECTION_HEADER) };
        let section_offset = section_header.PointerToRawData as usize;
        let section_size = section_header.SizeOfRawData as usize;

        // Add debug statement
        println!("Section {} Offset: {}, Size: {}", i + 1, section_offset, section_size);

        if section_offset > data.len() || section_size > data.len() - section_offset {
            println!("Section data is out of bounds: Offset {}, Size {}, File Length {}", section_offset, section_size, data.len());
            return Err(Box::from("Section data is out of bounds."));
        }

        let section_data = data[section_offset..section_offset + section_size].to_vec();
        let section_info = SectionInfo { header: *section_header, data: section_data };

        sections.push(section_info);
    }

    let pe_headers = data[..section_headers_start].to_vec();
    Ok((pe_headers, sections))
}






fn open_pe_file(path: &str) -> Result<HANDLE, std::io::Error> {
    let c_path = CString::new(path).unwrap();
    let handle = unsafe {
        CreateFileA(
            c_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    } else {
        Ok(handle)
    }
}

fn read_pe_headers(handle: HANDLE) -> Result<(IMAGE_DOS_HEADER, IMAGE_NT_HEADERS), std::io::Error> {
    let mut dos_header: IMAGE_DOS_HEADER = unsafe { std::mem::zeroed() };
    let mut nt_headers: IMAGE_NT_HEADERS = unsafe { std::mem::zeroed() };
    let mut read: DWORD = 0;

    // Read DOS header
    let success = unsafe {
        ReadFile(
            handle,
            &mut dos_header as *mut _ as LPVOID,
            std::mem::size_of::<IMAGE_DOS_HEADER>() as DWORD,
            &mut read,
            null_mut(),
        )
    };
    if success == 0 || read != std::mem::size_of::<IMAGE_DOS_HEADER>() as DWORD {
        return Err(std::io::Error::last_os_error());
    }
    println!("DOS header read successfully.");

    // Validate DOS header
    if dos_header.e_magic != 0x5A4D { // 'MZ' magic number
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid DOS header magic number"));
    }

    // Move to NT headers
    let nt_headers_offset = dos_header.e_lfanew as i32;
    println!("NT headers offset: {}", nt_headers_offset);

    let file_pointer = unsafe { SetFilePointer(handle, nt_headers_offset, null_mut(), FILE_BEGIN) };
    if file_pointer == INVALID_SET_FILE_POINTER {
        return Err(std::io::Error::last_os_error());
    }
    println!("File pointer set to NT headers offset successfully.");

    // Read NT headers
    let success = unsafe {
        ReadFile(
            handle,
            &mut nt_headers as *mut _ as LPVOID,
            std::mem::size_of::<IMAGE_NT_HEADERS>() as DWORD,
            &mut read,
            null_mut(),
        ) != 0
    };
    if !success || read != std::mem::size_of::<IMAGE_NT_HEADERS>() as DWORD {
        return Err(std::io::Error::last_os_error());
    }
    println!("NT headers read successfully.");

    Ok((dos_header, nt_headers))
}






fn close_pe_file(handle: HANDLE) -> std::io::Result<()> {
    let result = unsafe { CloseHandle(handle) };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    } else {
        Ok(())
    }
}

fn read_sections(handle: HANDLE, dos_header: &IMAGE_DOS_HEADER, nt_headers: &IMAGE_NT_HEADERS) -> Result<Vec<SectionInfo>, std::io::Error> {
    let number_of_sections = nt_headers.FileHeader.NumberOfSections as usize;
    let section_size = std::mem::size_of::<IMAGE_SECTION_HEADER>();
    let mut sections: Vec<SectionInfo> = Vec::with_capacity(number_of_sections);

    // Calculate the correct offset to the first section header
    let nt_headers_offset = dos_header.e_lfanew as usize;
    let section_headers_start = nt_headers_offset + std::mem::size_of::<IMAGE_NT_HEADERS>();

    println!("Reading section headers starting at offset: {}", section_headers_start);

    let file_pointer = unsafe { SetFilePointer(handle, section_headers_start as i32, null_mut(), FILE_BEGIN) };
    if file_pointer == INVALID_SET_FILE_POINTER {
        return Err(std::io::Error::last_os_error());
    }

    for i in 0..number_of_sections {
        let mut section_header: IMAGE_SECTION_HEADER = unsafe { std::mem::zeroed() };
        let mut read: DWORD = 0;
        let success = unsafe {
            ReadFile(
                handle,
                &mut section_header as *mut _ as LPVOID,
                section_size as DWORD,
                &mut read,
                null_mut(),
            ) != 0
        };
        if !success || read != section_size as DWORD {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Failed to read section header"));
        }

        println!("Section {} Name: {:?}", i + 1, section_header.Name);
        println!("Section {} Characteristics: 0x{:X}", i + 1, section_header.Characteristics);

        let section_data_offset = section_header.PointerToRawData as usize;
        let section_data_size = section_header.SizeOfRawData as usize;

        // Add debug statement
        println!("Section {} Data Offset: {}, Data Size: {}", i + 1, section_data_offset, section_data_size);

        // Validate the section data offset and size
        if section_data_offset >= u32::MAX as usize || section_data_size >= u32::MAX as usize {
            println!("Invalid section offset or size: Offset {}, Size {}", section_data_offset, section_data_size);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Section offset or size exceeds maximum allowable value"));
        }

        if section_data_offset + section_data_size > nt_headers.OptionalHeader.SizeOfImage as usize {
            println!("Section data exceeds image size: Offset {}, Size {}, Image Size {}", section_data_offset, section_data_size, nt_headers.OptionalHeader.SizeOfImage);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Section data exceeds image size."));
        }

        let mut section_data = vec![0u8; section_data_size];

        let success = unsafe {
            SetFilePointer(handle, section_data_offset as i32, null_mut(), FILE_BEGIN)
        };
        if success == INVALID_SET_FILE_POINTER {
            return Err(std::io::Error::last_os_error());
        }

        let success = unsafe {
            ReadFile(
                handle,
                section_data.as_mut_ptr() as LPVOID,
                section_data_size as DWORD,
                &mut read,
                null_mut(),
            ) != 0
        };
        if !success || read != section_data_size as DWORD {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Failed to read section data"));
        }

        sections.push(SectionInfo {
            header: section_header,
            data: section_data,
        });
    }

    Ok(sections)
}













fn create_new_section(data: &[u8], last_section: &SectionInfo) -> IMAGE_SECTION_HEADER {
    let virtual_address = (last_section.header.VirtualAddress + last_section.header.SizeOfRawData + 0xFFF) & !0xFFF;
    let size_of_raw_data = (data.len() as u32 + 0x1FF) & !0x1FF;
    let pointer_to_raw_data = last_section.header.PointerToRawData + last_section.header.SizeOfRawData;

    let mut new_section: IMAGE_SECTION_HEADER = unsafe { std::mem::zeroed() };
    new_section.Name.copy_from_slice(b".huff\0\0\0");
    new_section.VirtualAddress = virtual_address;
    new_section.SizeOfRawData = size_of_raw_data;
    new_section.PointerToRawData = pointer_to_raw_data;
    new_section.PointerToRelocations = 0;
    new_section.PointerToLinenumbers = 0;
    new_section.NumberOfRelocations = 0;
    new_section.NumberOfLinenumbers = 0;
    new_section.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    // Set the VirtualSize field in the Misc union
    unsafe {
        *new_section.Misc.VirtualSize_mut() = size_of_raw_data;
    }

    new_section
}


fn add_huffman_section(input_path: &str, output_path: &str, data: &[u8]) -> io::Result<()> {
    // Ensure the directory exists before opening the file
    if let Some(parent) = Path::new(output_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Open the input file and create the output file
    let mut input_file = OpenOptions::new().read(true).open(input_path)?;
    let mut output_file = OpenOptions::new().write(true).create(true).truncate(true).open(output_path)?;

    let handle = input_file.as_raw_handle() as HANDLE;

    // Read headers and sections from the input file
    let (dos_header, nt_headers) = read_pe_headers(handle)?;
    let mut sections = read_sections(handle, &dos_header, &nt_headers)?;

    // Write the DOS header to the output file
    output_file.write_all(unsafe { any_as_u8_slice(&dos_header) })?;

    // Write the NT headers to the output file
    output_file.write_all(unsafe { any_as_u8_slice(&nt_headers) })?;

    // Write each section header to the output file
    for section in &sections {
        output_file.write_all(unsafe { any_as_u8_slice(&section.header) })?;
    }

    // Write each section's data to the output file
    for section in &sections {
        output_file.write_all(&section.data)?;
    }

    // Create new section
    let last_section = sections.last().unwrap();
    let new_section_header = create_new_section(data, last_section);

    // Add the new section to the list and write it to the file
    let new_section = SectionInfo {
        header: new_section_header,
        data: data.to_vec(),
    };
    sections.push(new_section);

    // Write the new section header
    output_file.write_all(unsafe { any_as_u8_slice(&sections.last().unwrap().header) })?;

    // Append new section data to the end of the file
    output_file.write_all(data)?;

    Ok(())
}







/// Transmute a reference to T into a byte slice
/// Safety: Ensure that there are no uninit bytes in T (like padding in C structs)
unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    std::slice::from_raw_parts((p as *const T) as *const u8, std::mem::size_of::<T>())
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Debug, Serialize, Deserialize)]
struct HuffmanNode {
    symbol: Option<u8>,
    frequency: usize,
    left: Option<Box<HuffmanNode>>,
    right: Option<Box<HuffmanNode>>,
}

impl HuffmanNode {
    fn new_leaf(symbol: u8, frequency: usize) -> HuffmanNode {
        HuffmanNode {
            symbol: Some(symbol),
            frequency,
            left: None,
            right: None,
        }
    }

    fn new_internal(frequency: usize, left: HuffmanNode, right: HuffmanNode) -> HuffmanNode {
        HuffmanNode {
            symbol: None,
            frequency,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct HuffmanTree {
    root: HuffmanNode,
    table: HashMap<u8, Vec<bool>>,
}

impl HuffmanTree {
    fn from_frequencies(freq: HashMap<u8, usize>) -> Result<HuffmanTree, &'static str> {
        if freq.is_empty() {
            return Err("Frequency map is empty");
        }

        let mut heap = BinaryHeap::new();
        for (symbol, frequency) in &freq {
            println!("Symbol: {}, Frequency: {}", symbol, frequency); // Debug print
            heap.push((!frequency, HuffmanNode::new_leaf(*symbol, *frequency)));
        }

        while heap.len() > 1 {
            let (freq1, node1) = heap.pop().ok_or("Heap is empty during merge")?;
            let (freq2, node2) = heap.pop().ok_or("Heap is empty during merge")?;
            let merged = HuffmanNode::new_internal(!(!freq1 + !freq2), node1, node2);
            heap.push((!(!freq1 + !freq2), merged));
        }

        let root = heap.pop().ok_or("Heap is empty at end")?.1;
        let mut table = HashMap::new();
        build_table(&root, &mut table, Vec::new());

        Ok(HuffmanTree { root, table })
    }

    fn encode(&self, data: &[u8]) -> BitVec {
        let mut encoded = BitVec::new();
        for &symbol in data {
            if let Some(code) = self.table.get(&symbol) {
                for &bit in code {
                    encoded.push(bit);
                }
            }
        }
        encoded
    }

    fn decode(&self, bits: &BitVec) -> Vec<u8> {
        let mut decoded = Vec::new();
        let mut node = &self.root;
        for bit in bits {
            node = if bit {
                node.right.as_deref().unwrap()
            } else {
                node.left.as_deref().unwrap()
            };

            if let Some(symbol) = node.symbol {
                decoded.push(symbol);
                node = &self.root;
            }
        }
        decoded
    }
}


fn build_table(node: &HuffmanNode, table: &mut HashMap<u8, Vec<bool>>, mut path: Vec<bool>) {
    if let Some(symbol) = node.symbol {
        table.insert(symbol, path);
    } else {
        if let Some(ref left) = node.left {
            let mut left_path = path.clone();
            left_path.push(false);
            build_table(left, table, left_path);
        }
        if let Some(ref right) = node.right {
            let mut right_path = path.clone();
            right_path.push(true);
            build_table(right, table, right_path);
        }
    }
}

fn parse_arguments() -> ArgMatches {
    Command::new("Assembly Huffman Compressor")
        .version("1.0")
        .author("Your Name")
        .about("Compress or decompress assembly data using Huffman encoding")
        .arg(
            Arg::new("mode")
                .short('m')
                .long("mode")
                .value_parser(["pack", "unpack"])  // No leading dash for values
                .help("Mode: pack to compress, unpack to decompress")
                .required(true),
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_parser(clap::value_parser!(String))
                .help("Input file path")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_parser(clap::value_parser!(String))
                .help("Output file path")
                .required(true),
        )
        .get_matches()
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = parse_arguments();
    let mode = matches.get_one::<String>("mode").unwrap();
    let input_path = matches.get_one::<String>("input").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();

    match mode.as_str() {
        "pack" => compress(input_path, output_path)?,
        "unpack" => decompress(input_path, output_path)?,
        _ => println!("Unknown mode. Use 'pack' or 'unpack'."),
    }
    Ok(())
}
fn compress(input_path: &str, output_path: &str) -> Result<(), Box<dyn Error>> {
    // Open the input file and read its content
    let mut file = File::open(input_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Extract PE sections from the input file data
    let (pe_headers, sections) = extract_pe_sections(&data)?;

    let mut all_bytes = Vec::new();

    for section in &sections {
        let section_data = &section.data;
        if section_data.len() > 0 {
            all_bytes.extend(section_data);
        }
    }

    if all_bytes.is_empty() {
        return Err("No executable data found in sections".into());
    }

    // Build the frequency map from the collected bytes
    let freq_map = all_bytes.iter().fold(HashMap::new(), |mut acc, &byte| {
        *acc.entry(byte).or_insert(0) += 1;
        acc
    });

    println!("Frequency Map: {:?}", freq_map); // Debug print

    // Create the Huffman tree and encode the data
    let huffman_tree = HuffmanTree::from_frequencies(freq_map)?;
    let encoded_bits = huffman_tree.encode(&all_bytes);
    let encoded_bytes = encoded_bits.to_bytes();

    // Serialize the Huffman tree and prepare the output data
    let serialized_tree = serde_json::to_vec(&huffman_tree)?;
    let mut output_data = serialized_tree;
    output_data.push(0); // Separator
    output_data.extend_from_slice(&encoded_bytes);

    // Add the Huffman section to the PE file
    add_huffman_section(input_path, output_path, &output_data)?;

    Ok(())
}










fn decompress(input_path: &str, output_path: &str) -> Result<(), Box<dyn Error>> {
    // Open the input file and read its content
    let mut file = File::open(input_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Extract PE sections from the input file data
    let (_, sections) = extract_pe_sections(&data)?;

    let huffman_section = sections.iter().find(|s| {
        let name = String::from_utf8_lossy(&s.header.Name).trim_end_matches('\0').to_string();
        name == ".huff"
    }).ok_or("Huffman section not found")?;

    let huffman_data = &huffman_section.data;
    let split_index = huffman_data.iter().position(|&x| x == 0).ok_or("Failed to find separator")?;

    let serialized_tree = &huffman_data[..split_index];
    let encoded_bytes = &huffman_data[split_index + 1..];

    let huffman_tree: HuffmanTree = serde_json::from_slice(serialized_tree)?;
    let encoded_bits = BitVec::from_bytes(encoded_bytes);
    let decoded_bytes = huffman_tree.decode(&encoded_bits);

    fs::write(output_path, decoded_bytes)?;
    Ok(())
}











