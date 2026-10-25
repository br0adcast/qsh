#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    qsh_channel_fuzz::wire::exercise(input);
});
