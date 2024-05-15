use std::slice;
use std::arch::asm;
pub fn compress(input: &[u8], output: &mut [u8]) -> usize {
    let mut output_len: usize = 0;

    unsafe {
        let mut input_ptr = input.as_ptr();
        let mut input_len = input.len();
        let mut output_ptr = output.as_mut_ptr();
        let initial_output_ptr = output_ptr;

        asm!(
            "xor rcx, rcx",            // Clear run length counter
            "cmp rsi, 0",
            "je 5f",                   // If input length is 0, jump to done

            "2:",                      // Start loop
            "mov al, [rdi]",           // Load current byte
            "inc rdi",                 // Move to next byte
            "inc rcx",                 // Increment run length
            "dec rsi",                 // Decrement input length
            "jz 3f",                   // If end of input, jump to write_output

            "3:",                      // Compare byte
            "cmp al, [rdi]",           // Compare with next byte
            "jne 4f",                  // If different, jump to write_output
            "inc rdi",                 // Move to next byte
            "inc rcx",                 // Increment run length
            "dec rsi",                 // Decrement input length
            "jz 4f",                   // If end of input, jump to write_output
            "jmp 3b",                  // Repeat comparison

            "4:",                      // Write output
            "mov [rdx], al",           // Write byte to output
            "inc rdx",
            "mov [rdx], cl",           // Write run length to output
            "inc rdx",

            "xor rcx, rcx",            // Clear run length counter
            "cmp rsi, 0",
            "jne 2b",                  // Continue loop

            "5:",                      // Done
            inout("rdi") input_ptr,
            inout("rsi") input_len,
            inout("rdx") output_ptr,
            out("al") _, out("cl") _, options(nostack, preserves_flags)
        );

        output_len = output_ptr.offset_from(initial_output_ptr) as usize;
    }

    output_len
}



























