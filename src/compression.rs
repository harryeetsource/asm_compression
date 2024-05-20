use std::slice;
use std::arch::asm;
pub fn compress(input: &[u8], output: &mut [u8]) -> usize {
    let mut input_index = 0;
    let mut output_index = 0;

    while input_index < input.len() {
        let byte = input[input_index];
        let mut run_length = 1;

        // Count the run length
        while input_index + run_length < input.len() && run_length < u8::MAX as usize && input[input_index + run_length] == byte {
            run_length += 1;
        }

        // Write the byte and run length to the output
        output[output_index] = byte;
        output[output_index + 1] = run_length as u8;
        output_index += 2;

        // Move to the next segment
        input_index += run_length;
    }

    output_index
}



pub fn decompress(input: &[u8], output: &mut [u8]) -> usize {
    let mut input_index = 0;
    let mut output_index = 0;

    while input_index < input.len() {
        if input_index + 1 >= input.len() {
            break; // Prevent out-of-bounds access
        }
        let byte = input[input_index];
        let run_length = input[input_index + 1];
        input_index += 2;

        for _ in 0..run_length {
            output[output_index] = byte;
            output_index += 1;
        }
    }

    output_index
}






























