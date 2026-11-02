#![no_main]
use libfuzzer_sys::fuzz_target;

// An AirPlay 1 stream's packets as the library decodes them: ALAC with the classic fmtp, and an fmtp of the
// fuzzer's own (the first line of the input) for whatever stream shape it describes.
fuzz_target!(|data: &[u8]| {
    shairplay::fuzzing::rtp(
        "96 AppleLossless",
        "96 352 0 16 40 10 14 2 255 0 0 44100",
        data,
    );
    if let Some(i) = data.iter().position(|&b| b == b'\n')
        && let Ok(fmtp) = std::str::from_utf8(&data[..i])
    {
        shairplay::fuzzing::rtp("96 AppleLossless", fmtp, &data[i + 1..]);
        shairplay::fuzzing::rtp("96 L16/44100/2", "", &data[i + 1..]);
    }
});
