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
use winapi::um::fileapi::{CreateFileA, ReadFile, OPEN_EXISTING, SetFilePointer};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{MapViewOfFile, VirtualAlloc};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
use winapi::um::winbase::{FILE_BEGIN};
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    GENERIC_READ, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
};
use winapi::um::winnt::{IMAGE_SCN_MEM_EXECUTE};
use winapi::um::winnt::IMAGE_FILE_HEADER;
use std::mem;
use std::mem::{size_of, transmute};
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
    offset: usize,
    data: Vec<u8>,
}

fn extract_pe_sections(data: &[u8]) -> Result<(Vec<u8>, Vec<SectionInfo>, Vec<SectionInfo>), Box<dyn std::error::Error>> {
    // Ensure data is large enough to contain an IMAGE_DOS_HEADER
    if data.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err(Box::from("Data too short for IMAGE_DOS_HEADER"));
    }

    let dos_header = unsafe { &*(data.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != 0x5A4D { // 'MZ' magic number check
        return Err(Box::from("Invalid DOS header."));
    }

    let nt_headers_offset = dos_header.e_lfanew as usize;
    if data.len() < nt_headers_offset + std::mem::size_of::<u32>() {
        return Err(Box::from("Invalid NT headers offset."));
    }

    // Verify the 'PE\0\0' signature
    let signature = unsafe { *(data.as_ptr().add(nt_headers_offset) as *const u32) };
    if signature != 0x00004550 {
        return Err(Box::from("Invalid PE signature."));
    }

    // Determine the correct NT headers based on architecture
    let file_header = unsafe { &*(data.as_ptr().add(nt_headers_offset + 4) as *const IMAGE_FILE_HEADER) };
    let optional_header_size = file_header.SizeOfOptionalHeader as usize;
    let section_headers_start = nt_headers_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + optional_header_size;

    let mut compressed_sections = Vec::new();
    let mut uncompressed_sections = Vec::new();

    for i in 0..file_header.NumberOfSections as usize {
        let section_header: &IMAGE_SECTION_HEADER = unsafe { &*(data.as_ptr().add(section_headers_start + i * std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const IMAGE_SECTION_HEADER) };
        let section_offset = section_header.PointerToRawData as usize;
        let section_size = section_header.SizeOfRawData as usize;

        if section_offset + section_size > data.len() {
            println!("Section exceeds file length: Offset {}, Size {}, File Length {}", section_offset, section_size, data.len());
            return Err(Box::from("Section data exceeds file length."));
        }

        let section_data = data[section_offset..section_offset + section_size].to_vec();
        let section_info = SectionInfo { offset: section_offset, data: section_data };

        if section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            compressed_sections.push(section_info);
        } else {
            uncompressed_sections.push(section_info);
        }
    }

    let pe_headers = data[..section_headers_start].to_vec();
    Ok((pe_headers, compressed_sections, uncompressed_sections))
}



fn find_pe_header_end(data: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    // Parse the DOS header
    let dos_header = unsafe { &*(data.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != 0x5A4D {
        return Err(Box::from("Invalid DOS header."));
    }

    // Locate the NT headers
    let nt_headers_offset = dos_header.e_lfanew as usize;
    let nt_signature = unsafe { *(data[nt_headers_offset..].as_ptr() as *const u32) };
    if nt_signature != 0x00004550 {
        return Err(Box::from("Invalid NT header signature."));
    }

    // Find the first section's offset
    let first_section_offset = nt_headers_offset + mem::size_of::<IMAGE_NT_HEADERS64>();
    Ok(first_section_offset)
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
    fn from_frequencies(freq: HashMap<u8, usize>) -> HuffmanTree {
        let mut heap = BinaryHeap::new();
        for (symbol, frequency) in freq {
            heap.push((!frequency, HuffmanNode::new_leaf(symbol, frequency)));
        }

        while heap.len() > 1 {
            let (freq1, node1) = heap.pop().unwrap();
            let (freq2, node2) = heap.pop().unwrap();
            let merged = HuffmanNode::new_internal(!(!freq1 + !freq2), node1, node2);
            heap.push((!(!freq1 + !freq2), merged));
        }

        let root = heap.pop().unwrap().1;
        let mut table = HashMap::new();
        build_table(&root, &mut table, Vec::new());

        HuffmanTree { root, table }
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

fn build_table(node: &HuffmanNode, table: &mut HashMap<u8, Vec<bool>>, prefix: Vec<bool>) {
    if let Some(symbol) = node.symbol {
        table.insert(symbol, prefix);
    } else {
        let mut left_prefix = prefix.clone();
        left_prefix.push(false);
        build_table(node.left.as_deref().unwrap(), table, left_prefix);

        let mut right_prefix = prefix;
        right_prefix.push(true);
        build_table(node.right.as_deref().unwrap(), table, right_prefix);
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


fn compress(input: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(input)?;
    let (pe_headers, compressed_sections, uncompressed_sections) = extract_pe_sections(&data)?;

    let mut freq_map = std::collections::HashMap::new();
    for section in &compressed_sections {
        for &byte in &section.data {
            *freq_map.entry(byte).or_insert(0) += 1;
        }
    }

    let huffman_tree = HuffmanTree::from_frequencies(freq_map);
    let mut all_bytes = Vec::new();
    for section in &compressed_sections {
        all_bytes.extend_from_slice(&section.data);
    }

    let encoded_bits = huffman_tree.encode(&all_bytes);
    let encoded_bytes = encoded_bits.to_bytes();

    let serialized_tree = serde_json::to_string(&huffman_tree)?;
    let mut output_data = Vec::new();
    output_data.extend_from_slice(serialized_tree.as_bytes());
    output_data.push(0);  // Separator
    output_data.extend_from_slice(&encoded_bytes);

    // Determine the maximum required size for final_data
    let max_offset = uncompressed_sections.iter()
        .chain(compressed_sections.iter())
        .map(|s| s.offset + s.data.len())
        .max()
        .unwrap_or(0);
    
    let final_size = std::cmp::max(pe_headers.len() + output_data.len(), max_offset);
    let mut final_data = vec![0; final_size];
    final_data[..pe_headers.len()].copy_from_slice(&pe_headers);

    // Correctly calculate where the compressed data should start
    let data_start_offset = pe_headers.len();
    final_data[data_start_offset..data_start_offset + output_data.len()].copy_from_slice(&output_data);

    // Ensure uncompressed sections fit within the array bounds
    for section in &uncompressed_sections {
        if section.offset + section.data.len() <= final_data.len() {
            final_data[section.offset..(section.offset + section.data.len())].copy_from_slice(&section.data);
        }
    }

    std::fs::write(output, final_data)?;
    Ok(())
}

fn decompress(input: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read the entire compressed file
    let compressed_data = std::fs::read(input)?;

    // Extract the PE headers and sections (to retrieve compressed section offsets)
    let (pe_headers, compressed_sections, uncompressed_sections) = extract_pe_sections(&compressed_data)?;

    // Ensure there are compressed sections to decode
    if compressed_sections.is_empty() {
        return Err(Box::from("No compressed sections found"));
    }

    // Aggregate all compressed sections into a single vector to find the separator
    let mut all_compressed_data = Vec::new();
    for section in &compressed_sections {
        all_compressed_data.extend_from_slice(&compressed_data[section.offset..section.offset + section.data.len()]);
    }

    // Find the separator (byte `0`) that separates the serialized Huffman tree from encoded data
    let split_index = all_compressed_data.iter().position(|&x| x == 0).ok_or("Failed to find separator")?;

    // Separate the serialized tree and the encoded bytes
    let serialized_tree = &all_compressed_data[..split_index];
    let encoded_bytes = &all_compressed_data[split_index + 1..];

    // Deserialize the Huffman tree
    let huffman_tree: HuffmanTree = serde_json::from_slice(serialized_tree)
        .map_err(|e| format!("Failed to deserialize Huffman tree: {}", e))?;

    // Decode the bit-encoded data using the Huffman tree
    let encoded_bits = BitVec::from_bytes(encoded_bytes);
    let decoded_bytes = huffman_tree.decode(&encoded_bits);

    // Create the final decompressed data vector with the original size
    let mut decompressed_data = vec![0; compressed_data.len()];
    decompressed_data[..pe_headers.len()].copy_from_slice(&pe_headers);

    // Replace each compressed section with the decompressed data
    let mut decoded_offset = 0;
    for section in &compressed_sections {
        let section_size = section.data.len();
        decompressed_data[section.offset..(section.offset + section_size)]
            .copy_from_slice(&decoded_bytes[decoded_offset..(decoded_offset + section_size)]);
        decoded_offset += section_size;
    }

    // Place uncompressed sections back at their original offsets
    for section in &uncompressed_sections {
        decompressed_data[section.offset..(section.offset + section.data.len())]
            .copy_from_slice(&section.data);
    }

    // Write the final data to the output file
    std::fs::write(output, decompressed_data)?;
    println!("Decompressed data saved to {}", output);
    Ok(())
}







