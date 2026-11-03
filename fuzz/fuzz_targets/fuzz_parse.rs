#![no_main]
//! The wire-parser surface: `yara_types::parse` on arbitrary bytes. banken reads these lines from
//! the sensor's stream, so a hostile or truncated line must degrade a detection, never crash the
//! reader (the mimi parser's bar).
//!
//! Two properties:
//!   1. parse never panics on any input (valid UTF-8 or not -- `parse` takes `&str`, so non-UTF-8
//!      is skipped as it would be upstream of a line reader).
//!   2. a line that parses round-trips: render(parse(line)) parses again to the same value, so the
//!      type is a stable fixpoint and banken and the sensor cannot disagree on a line they both
//!      accept.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // banken reads newline-delimited UTF-8; a byte stream that is not UTF-8 never reaches `parse`.
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(parsed) = yara_types::parse(line) {
        // Rendering a parsed value must itself parse back to an equal value: a stable fixpoint.
        let rendered = yara_types::render(&parsed);
        let reparsed = yara_types::parse(&rendered).expect("a rendered Match re-parses");
        assert_eq!(parsed, reparsed, "parse -> render -> parse must be stable");
    }
});
