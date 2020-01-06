#include "pch.h"
#include "tlv_parser.h"
#include <exception>
#include <string>
#include <iostream>

static std::vector<std::string> string_array_tag_class = {
	"Universal", "Application", "Context-Specific", "Private"
};
static std::vector<std::string> string_array_tag = {
	"BER", "BOOLEAN", "INTEGER", "BIT_STRING",
	"OCTET_STRING","NULL", "OBJECT_IDENTIFIER", "OBJECT_DESCRIPTOR",
	"EXTERNAL", "REAL", "ENUMERATED", "EMBEDDED_PDV",
	"UTF8String", "RELATIVE_OID", "Reserved(14)", "Reserved(15)","SEQUENCE",
	"SET", "NumericString", "PrintableString", "T61String",
	"VideotexString","IA5String", "UTCTime", "GeneralizedTime",
	"GraphicString", "VisibleString", "GeneralString", "UniversalString",
	"CHARACTER_STRING", "BMPString", "DATE", "TIME_OF_DAY",
	"DATE_TIME", "DURATION", "OID_IRI", "RELATIVE_OID_IRI",
};

tlv_parser::tlv::tlv(const enum_tag t, const enum_tag_class t_class, const bool t_constructed, const bool indefinite, const unsigned long l, unsigned char * buffer)
{
	tag = t;
	tag_class = t_class;
	tag_constructed = t_constructed;

	is_indefinite = indefinite;
	length = l;

	if (length > 0)
	{
		value.resize(length);
		memcpy_s(&value[0], length, buffer, length);
	}
}

void intent_string(std::string & s, const unsigned intent)
{
	if (intent > 0)
	{
		s.append("|");
		for (auto i = 0; i < intent; i++)
			s.append("-");
	}
}

void tlv_parser::tlv::append_value_as_hex(std::string & s)
{
	char buffer[] = "00";
	for (auto i = 0; i < value.size(); i++)
	{
		sprintf_s(buffer, "%02x", value[i]);
		s.append(buffer);
	}
}

std::string tlv_parser::tlv::to_string(const unsigned intent)
{
	std::string s;
	intent_string(s, intent);

	if (tag_class == class_universal)
	{
		s.append(string_array_tag[tag]);

		if (!is_indefinite)
			s.append(": Length " + std::to_string(length));
		else
			s.append(": Length (indefinite) " + std::to_string(length));

		if (!tag_constructed)
		{
			s.append(", ");

			switch (tag)
			{
			case tag_object_identifier:
				{
					append_value_as_hex(s);
					s.append(" => ");

					std::string buffer;

					buffer.append(std::to_string(value[0] / 40));
					buffer.append(".");
					buffer.append(std::to_string(value[0] % 40));
					for (auto i = 1; i < value.size(); i++)
					{
						unsigned long v = value[i];
						buffer.append(".");
						if (v & 0x80)
						{
							v &= 0x7f;
							unsigned char u;
							do
							{
								u = value[++i];
								v <<= 7;
								v |= u & 0x7f;
							} while (u & 0x80);
						}
						
						buffer.append(std::to_string(v));
					}

					s.append("'" + buffer + "'");
				}
				break;

			case tag_boolean:
				if (value[0] == 0)
					s.append("FALSE");
				else if (value[0] == 0xff || value[0] == 1)
					s.append("TRUE");
				else
					s.append("???");
				break;

			case tag_numeric_string:
			case tag_ia5_string:
			case tag_utf8_string:
			case tag_printable_string:
			case tag_t61_string:
			case tag_utc_time:
			case tag_generalized_time:
				{
					append_value_as_hex(s);
					s.append(" => ");

					std::string buffer;
					buffer.resize(value.size());
					memcpy_s(&buffer[0], buffer.size(), &value[0], value.size());
					s.append("'" + buffer + "'");
				}
				break;

			default:
				append_value_as_hex(s);
				break;
			}
		}
	}
	else if (tag_class == class_context_specific)
	{
		if (!is_indefinite)
			s.append("[" + std::to_string(tag) + "]"
				//+ string_array_tag_class[tag_class] + (tag_constructed ? ":CONSTRUCTED" : ":PRIMITIVE")
				+ ", Length " + std::to_string(length));
		else
			s.append("[" + std::to_string(tag) + "]"
				//+ string_array_tag_class[tag_class] + (tag_constructed ? ":CONSTRUCTED" : ":PRIMITIVE")
				+ ", Length (indefinite) " + std::to_string(length));

		if (!tag_constructed)
		{
			s.append(", ");
			append_value_as_hex(s);
		}
	}
	else
	{
		// Can this happen?
		s.append(string_array_tag_class[tag_class] + ":");
		tag_constructed ? s.append("CONSTRUCTED:") : s.append("PRIMITIVE:");

		if (!is_indefinite)
			s.append("(TAG " + std::to_string(tag) + ", Length " + std::to_string(length) + ")");
		else
			s.append("(TAG " + std::to_string(tag) + ", Length (indefinite) " + std::to_string(length) + ")");

		if (!tag_constructed)
		{
			s.append(", ");
			append_value_as_hex(s);
		}
	}

	return s;
}

void tlv_parser::tlv::print(tlv * root, unsigned intent) const
{
	std::cout << root->to_string(intent) << std::endl;
	++intent;
	for (auto c : root->childs)
		print(c, intent);
}

void tlv_parser::tlv::print()
{
	print(this, 0);
}

tlv_parser::tlv::enum_tag tlv_parser::read_tag(const unsigned char * buffer, unsigned int & index, tlv::enum_tag_class & tag_class, bool & tag_constructed)
{
	unsigned long tag = buffer[index];

	tag_class = static_cast<tlv::enum_tag_class>(tag >> 6);
	tag_constructed = ((tag >> 5) & 0x1) > 0;

	tag &= 0x1f;

	if (tag == 0x1f)
	{
		tag = 0;

		unsigned char temp;
		do
		{
			tag <<= 7;
			temp = buffer[++index];
			tag |= temp & 0x7f;
		} while ((temp & 0x80) > 0);
	}

	return static_cast<tlv::enum_tag>(tag);
}

unsigned long tlv_parser::read_length(const unsigned char * buffer, unsigned int & index)
{
	unsigned long len = buffer[++index];
	if (len & 0x80)
	{
		const auto count = len & 0x7f;
		len = 0;
		for (auto i = 0; i < count; i++)
		{
			len <<= 8;
			len |= buffer[++index];
		}
	}

	return len;
}

void tlv_parser::parse(tlv * tlv)
{
	const auto childs = parse(&tlv->value[0], tlv->value.size());
	if (childs.size() > 0)
		tlv->childs = childs;
}

unsigned int tlv_parser::parse_indefinite_length(unsigned char* buffer)
{
	unsigned int index = 0;

	while (true)
	{
		tlv::enum_tag_class tag_class;
		bool tag_constructed;
		const auto tag = read_tag(buffer, index, tag_class, tag_constructed);
		const auto length = read_length(buffer, index);
		
		if (tag != tlv::tag_null && length == 0)
		{
			index += parse_indefinite_length(&buffer[++index]);
		}
		else
			index += length + 1;

		if (buffer[index] == 0 && buffer[index + 1] == 0)
		{
			index += 2;
			break;
		}
	}

	return index;
}

std::vector<tlv_parser::tlv *> tlv_parser::parse(unsigned char * buffer, const unsigned int max_len)
{
	unsigned int index = 0;
	std::vector<tlv *> result;

	tlv *prev_tlv = nullptr;
	do
	{
		tlv::enum_tag_class tag_class;
		bool tag_constructed;
		const auto tag = read_tag(buffer, index, tag_class, tag_constructed);
		auto length = read_length(buffer, index);

		tlv* act_tlv;
		if (tag != tlv::tag_null && length == 0)
		{
			//throw std::exception("Indefinite length encoding is not supported");
			length = parse_indefinite_length(&buffer[++index]);
			act_tlv = new tlv(tag, tag_class, tag_constructed, true, length - 2, &buffer[index]);
		}
		else
		{
			act_tlv = new tlv(tag, tag_class, tag_constructed, false, length, &buffer[++index]);
		}
		
		result.push_back(act_tlv);

		if (prev_tlv != nullptr)
			prev_tlv->next = act_tlv;

		prev_tlv = act_tlv;

		index += length;

	} while (index < max_len);

	if (index != max_len)
		throw std::exception("index != max_len");

	for (auto tlv : result)
	{
		if (tlv->tag_constructed)
			parse(tlv);
	}

	return result;
}
