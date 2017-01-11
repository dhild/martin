//! A Rust library for dealing with resource records and other DNS concepts.
#![doc(html_root_url = "https://dhild.github.io/dns-rs/")]
#![deny(missing_docs,
        missing_debug_implementations, missing_copy_implementations,
        trivial_casts, trivial_numeric_casts,
        unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]
#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
pub mod names;
pub mod rr;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
