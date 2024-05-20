use std::slice;
use std::arch::asm;
pub fn compress(input: &[u8], output: &mut [u8]) -> usize {
    unsafe {
        let mut input_ptr = input.as_ptr();
        let mut input_len = input.len();
        let mut output_ptr = output.as_mut_ptr();
        let initial_output_ptr = output_ptr;

        asm!(
            "xor rcx, rcx",            // Clear run length counter
            "test rsi, rsi",
            "je 2f",                   // If input length is 0, jump to done

            "3:",                      // Loop condition check
            "cmp rsi, 0",
            "je 5f",                   // If input length is 0, jump to final done

            "mov al, [rdi]",           // Load current byte
            "mov bl, al",              // Store current byte in bl for comparison
            "inc rdi",                 // Move to next byte
            "dec rsi",                 // Decrement input length
            "xor rcx, rcx",            // Clear run length counter

            "4:",                      // Count run length
            "inc rcx",                 // Increment run length
            "cmp rsi, 0",              // Check if input length is 0
            "je 6f",                   // If end of input, jump to write_output

            "cmp bl, [rdi]",           // Compare stored byte with next byte
            "jne 6f",                  // If different, jump to write_output
            "inc rdi",                 // Move to next byte
            "dec rsi",                 // Decrement input length
            "jmp 4b",                  // Repeat counting

            "6:",                      // Write output
            "mov [rdx], bl",           // Write byte to output
            "inc rdx",
            "mov [rdx], cl",           // Write run length to output
            "inc rdx",

            "jmp 3b",                  // Continue loop

            "2:",                      // Done
            "5:",                      // Final done
            inout("rdi") input_ptr,
            inout("rsi") input_len,
            inout("rdx") output_ptr,
            out("al") _, out("bl") _, out("cl") _, options(nostack, preserves_flags)
        );

        let output_len = output_ptr.offset_from(initial_output_ptr) as usize;
        output_len
    }
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






























