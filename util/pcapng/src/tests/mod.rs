mod blocks;
mod reader;
mod writer;

const SAMPLE_HTTP_GET: &[u8] = include_bytes!("examples/http-get.pcapng").as_slice();
const SAMPLE_RAW_IP_PACKETS: &[u8] = include_bytes!("examples/raw-ip.pcapng").as_slice();
