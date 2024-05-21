use std::slice;
use std::arch::asm;
use rand::Rng;

const HEADER_SIZE: usize = 8; // 4 bytes for new offset, 4 bytes for chunk size

pub fn compress(input: &[u8], output: &mut [u8]) -> usize {
    let mut rng = rand::thread_rng();
    let file_size = input.len();
    let chunk_size = rng.gen_range(1024..=file_size / 2);
    let new_offset = rng.gen_range(0..file_size - chunk_size);

    // Create a temporary buffer to rearrange the input data
    let mut temp = input.to_vec();

    // Move the header chunk to the new offset
    let header_chunk = temp[..chunk_size].to_vec(); // Copy the header chunk
    if new_offset > chunk_size {
        // Shift data to fill the gap left by moving the chunk out
        temp.copy_within(chunk_size..new_offset, 0);
    }
    // Place the chunk at its new position
    temp[new_offset..new_offset + chunk_size].copy_from_slice(&header_chunk);

    // Perform RLE compression on the rearranged input data
    let mut input_index = 0;
    let mut output_index = HEADER_SIZE;
    while input_index < temp.len() {
        let byte = temp[input_index];
        let mut run_length = 1;
        while input_index + run_length < temp.len() && run_length < u8::MAX as usize && temp[input_index + run_length] == byte {
            run_length += 1;
        }
        // Ensure there's enough space in the output buffer
        if output_index + 2 >= output.len() {
            break; // Prevent buffer overflow
        }
        output[output_index] = byte;
        output[output_index + 1] = run_length as u8;
        output_index += 2;
        input_index += run_length;
    }

    // Write the metadata in the header of the output
    output[0..4].copy_from_slice(&(new_offset as u32).to_le_bytes());
    output[4..8].copy_from_slice(&(chunk_size as u32).to_le_bytes());

    output_index
}










pub fn decompress(input: &[u8], output: &mut [u8]) -> usize {
    let new_offset = u32::from_le_bytes(input[0..4].try_into().unwrap()) as usize;
    let chunk_size = u32::from_le_bytes(input[4..8].try_into().unwrap()) as usize;

    let mut input_index = HEADER_SIZE;
    let mut output_index = 0;

    // Perform RLE decompression
    while input_index < input.len() {
        if input_index + 1 >= input.len() {
            break; // Safety check to prevent out-of-bounds access
        }
        let byte = input[input_index];
        let run_length = input[input_index + 1];
        input_index += 2;

        for _ in 0..run_length {
            if output_index < output.len() {
                output[output_index] = byte;
            }
            output_index += 1;
        }
    }

    // Rearrange the decompressed data to its original form
    // Create a buffer to temporarily hold the moved chunk
    let mut temp_chunk = vec![0u8; chunk_size];
    // Copy the moved chunk back into the temporary buffer
    temp_chunk.copy_from_slice(&output[new_offset..new_offset + chunk_size]);
    // If the new offset is greater than chunk size, shift data at the beginning up to new offset
    if new_offset > chunk_size {
        for i in (chunk_size..new_offset).rev() {
            output[i] = output[i - chunk_size];
        }
    }
    // Place the original chunk back at the start
    output[..chunk_size].copy_from_slice(&temp_chunk);

    output_index
}




































