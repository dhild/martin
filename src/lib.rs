#![doc(html_root_url = "https://dhild.github.io/dns-rs/")]
#![deny(missing_debug_implementations, missing_copy_implementations,
        trivial_casts, trivial_numeric_casts,
        unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]
pub mod names;
pub mod rr;

mod resource_records;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
