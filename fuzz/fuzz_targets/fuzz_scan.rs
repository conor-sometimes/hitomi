#![no_main]
//! The untrusted-input surface: scanning file bytes. A fixed rule set is compiled ONCE (lazily,
//! reused across every run in the process) and then arbitrary fuzzer bytes are scanned against it.
//!
//! The contract under test is the sensor's never-die bar (design section 2.2): no file content,
//! however crafted, may panic the scanner. A yara-x scan error is a value the engine returns (and
//! the daemon caches as `failed`), never a crash. The rule set stays fixed because rule text is
//! operator-supplied, not attacker-supplied; the scanned bytes are the hostile input.
//!
//! The marker in the rule is a benign synthetic string, never the EICAR test string (which is
//! never committed to source); matching behaviour is proven at runtime elsewhere.

use libfuzzer_sys::fuzz_target;
use std::cell::OnceCell;

use hitomi::Engine;

thread_local! {
    // One compiled Engine per worker thread; libfuzzer drives one thread per process, so this
    // compiles once and every run reuses it. `thread_local` avoids requiring `Engine: Sync`.
    static ENGINE: OnceCell<Engine> = const { OnceCell::new() };
}

fn fixed_ruleset() -> Engine {
    let rule = r#"
        rule hitomi_fuzz_marker : fuzz {
            meta:
                score = 10
                description = "hitomi fuzz marker"
            strings:
                $a = "hitomi-fuzz-marker"
                $b = { 48 49 54 4f 4d 49 }
                $c = /hitomi[0-9]{1,4}fuzz/
            condition:
                any of them
        }
    "#;
    Engine::from_sources(vec![("fuzz.yar".to_string(), rule.to_string())])
        .expect("the fixed fuzz rule set compiles")
}

fuzz_target!(|data: &[u8]| {
    ENGINE.with(|cell| {
        let engine = cell.get_or_init(fixed_ruleset);
        // Must not panic for any input. The result (Ok with hits, Ok clean, or Err) is all fine;
        // only a panic or UB fails the target.
        let _ = engine.scan_bytes(data);
    });
});
