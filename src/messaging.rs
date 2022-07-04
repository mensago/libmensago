// This module implements the data serialization for the client-server commands using a new
// lightweight self-documenting binary format called JBinPack. JBinPack was inspired by the
// Netstring format. Because Mensago communications are UTF-8 text-based, this module uses only a
// part of the format: messages are sent as String or BigString. String supports data up to 64KiB,
// which easily accommodates regular Mensago commands. Bulk data uploads and downloads are handled
// with HugeString, which can accommodate individual file sizes of up to 16EiB.
//
// The String format consists of a 1-byte value 14, a 2-byte MSB-order length code, and the
// data follows. The string "ABC123" would be encoded as `0e 00 06 41 42 43 31 32 33`.
//
// The HugeString format consists of a 1-byte value 14, an 8-byte MSB-order length code, and the
// data follows. The string "ABC123" encoded as a HugeString would be encoded similar to the above: 
// `10 00 00 00 00 00 00 00 06 41 42 43 31 32 33`.
//
// Mensago commands originally used JSON both for the command format and for the data serialization
// format, leading to a lot of character escaping. Using JBinPack for data serialization keeps
// things lightweight and eliminates all escaping. If the need to send binary data over the wire
// were needed at some point in the future, literally the only change needed would be the type
// codes.

// DataFrame is a structure for the lowest layer of network interaction. It represents a segment of
// data. Depending on the type code for the instance, it may indicate that
// the data payload is complete -- the SingleFrame type -- or it may be part of a larger set. In
// all cases a DataFrame is required to be equal to or smaller than the buffer size negotiated
// between the local host and the remote host.
#[derive(Debug)]
struct DataFrame {
	buffer: Vec::<u8>,
	index: usize,
}

impl DataFrame {

	fn new(bufferSize: usize) -> Option<DataFrame> {

		if bufferSize < 1024 {
			return None
		}

		Some(DataFrame {
			buffer: Vec::<u8>::new(),
			index: 0,
		})
	}
}

