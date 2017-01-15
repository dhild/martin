use header::Header;
use question::Question;
use rr::ResourceRecord;

/// Describes a DNS query or response.
#[warn(missing_debug_implementations)]
pub struct Message<'a> {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<&'a (ResourceRecord + 'a)>,
    authorities: Vec<&'a (ResourceRecord + 'a)>,
    additionals: Vec<&'a (ResourceRecord + 'a)>,
}
