#include "base85.h"

const char *B85_TO_CHAR =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

bool byte_to_c85(const char &c85, unsigned char &out) {

	if (c85 > 84) return false;

	out = B85_TO_CHAR[(unsigned char)c85];
	return true;
}

unsigned char c85_to_byte(const unsigned char &b)
{
	if (b >= '0' && b <= '9') return b - '0';
	if (b >= 'A' && b <= 'Z') return b - 'A' + 10;
	if (b >= 'a' && b <= 'z') return b - 'a' + 36;

	switch (b)
	{
		case '!': return 62;
		case '#': return 63;
		case '$': return 64;
		case '%': return 65;
		case '&': return 66;
		case '(': return 67;
		case ')': return 68;
		case '*': return 69;
		case '+': return 70;
		case '-': return 71;
		case ';': return 72;
		case '<': return 73;
		case '=': return 74;
		case '>': return 75;
		case '?': return 76;
		case '@': return 77;
		case '^': return 78;
		case '_': return 79;
		case '`': return 80;
		case '{': return 81;
		case '|': return 82;
		case '}': return 83;
		case '~': return 84;
		default:
			break;
	}

	// We should never be here
	return 255;
}

//! Encodes binary data into a Base85-encoded string
void base85encode(const QByteArray &ba, QString &out)
{
	out.clear();
	if (ba.length() == 0) return;

	size_t length = ba.length();
	size_t chunk_count = (length / 4);
	size_t data_index = 0;

	for (size_t i = 0; i < chunk_count; i++)
	{
		uint32_t decnum = ((uint32_t)ba[data_index]) << 24
			| ((uint32_t)ba[data_index + 1]) << 16
			| ((uint32_t)ba[data_index + 2]) << 8
			| ((uint32_t)ba[data_index + 3]);
		
		unsigned char converted = 0;
		byte_to_c85((size_t)decnum / 52200625, converted);
		out.push_back(QChar(converted));
		size_t remainder = (size_t)decnum % 52200625;
		byte_to_c85((remainder / 614125), converted);
		out.push_back(QChar(converted));
		remainder %= 614125;
		byte_to_c85((remainder / 7225), converted);
		out.push_back(QChar(converted));
		remainder %= 7225;
		byte_to_c85((remainder / 85), converted);
		out.push_back(QChar(converted));
		byte_to_c85((remainder % 85), converted);
		out.push_back(QChar(converted));

		data_index += 4;
	}

	size_t extra_bytes = length % 4;
	if (extra_bytes != 0)
	{
		uint32_t last_chunk = 0;

		for (size_t i = length - extra_bytes; i < length; i++)
		{
			last_chunk <<= 8;
			last_chunk |= (uint32_t) ba[i];
		}

		// Pad extra bytes with zeroes
		auto i = 4 - extra_bytes;
		while (i > 0)
		{
			last_chunk <<= 8;
			i--;
		}
		
		unsigned char converted = 0;
		byte_to_c85((size_t)last_chunk / 52200625, converted);
		out.push_back(QChar(converted));
		size_t remainder = (size_t)last_chunk % 52200625;
		byte_to_c85(remainder / 614125, converted);
		out.push_back(QChar(converted));
		
		if (extra_bytes > 1)
		{
			remainder %= 614125;
			byte_to_c85(remainder / 7225, converted);
			out.push_back(QChar(converted));

			if (extra_bytes > 2)
			{
				remainder %= 7225;
				byte_to_c85(remainder / 85, converted);
				out.push_back(QChar(converted));
			}
		}
	}
}

//! Decodes a Base85-encoded string into binary data
bool base85decode(const QString &s, QByteArray &out)
{
	size_t length = s.length();
	out.clear();
	
	if (length == 0) {
		return false;
	}
	
	uint32_t accumulator = 0;
	uint32_t in_index = 0;
	uint32_t chunk_count = length / 5;
	for (uint32_t chunk = 0; chunk < chunk_count; chunk++)
	{
		accumulator = 0;
		for (auto i = 0; i < 5; i++)
		{
			if (s[in_index].isSpace()) 
			{
				i--;
				in_index++;
				continue;
			}
			
			unsigned char c = c85_to_byte(s[in_index].toLatin1());
			accumulator = (accumulator * 85) + (uint32_t)c;
			in_index++;
		}

		out.push_back((char)(accumulator >> 24));
		out.push_back((char)((accumulator >> 16) & 255));
		out.push_back((char)((accumulator >> 8) & 255));
		out.push_back((char)(accumulator & 255));
	}
	
	auto remainder = length % 5;
	if (remainder > 0)
	{
		accumulator = 0;

		for (uint32_t i = 0; i < 5; i++)
		{
			unsigned char c;
			if (i < remainder)
			{
				// Ignore whitespace
				if (s[in_index].isSpace()) 
				{
					i--;
					in_index++;
					continue;
				}

				c = c85_to_byte(s[in_index].toLatin1());
			}
			else
			{
				c = 126;
			}
			accumulator = (accumulator * 85) + (uint32_t)c;
			in_index++;
		}

		switch (remainder) {
			case 4:
			{
				out.push_back((char)(accumulator >> 24));
				out.push_back((char)((accumulator >> 16) & 255));
				out.push_back((char)((accumulator >> 8) & 255));
				break;
			}
			case 3:
			{
				out.push_back((char)(accumulator >> 24));
				out.push_back((char)((accumulator >> 16) & 255));
				break;
			}
			case 2:
			{
				out.push_back((char)(accumulator >> 24));
				break;
			}
		}
	}

	return true;
}
