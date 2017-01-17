use header::Header;
use question::Question;
use rr::ResourceRecord;

/// Describes a DNS query or response.
#[warn(missing_debug_implementations)]
pub struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authorities: Vec<ResourceRecord>,
    additionals: Vec<ResourceRecord>,
}
