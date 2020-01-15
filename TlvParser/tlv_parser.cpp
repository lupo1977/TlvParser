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

tlv_parser::tlv::tlv(enum_tag t, enum_tag_class t_class, bool t_constructed, bool indefinite, unsigned long l, unsigned char* buffer)
{
	tag = t;
	tag_class = t_class;
	tag_constructed = t_constructed;

	is_indefinite = indefinite;
	length = l;

	if (length > 0 && buffer != nullptr)
	{
		value.resize(length);
		memcpy_s(&value[0], length, buffer, length);
	}
}

void intent_string(std::string& s, const unsigned intent)
{
	if (intent > 0)
	{
		s.append("|");
		for (unsigned i = 0; i < intent; i++)
			s.append("-");
	}
}

void tlv_parser::tlv::append_value_as_hex(std::string& s)
{
	char buffer[] = "00";
	for (auto i : value)
	{
		sprintf_s(buffer, "%02x", i);
		s.append(buffer);
	}
}

std::string tlv_parser::tlv::to_string(const unsigned intent)
{
	std::string s;
	intent_string(s, intent);

	if (tag_class == enum_tag_class::class_universal)
	{
		s.append(string_array_tag[static_cast<int>(tag)]);

		if (!is_indefinite)
			s.append(": Length " + std::to_string(length));
		else
			s.append(": Length (indefinite) " + std::to_string(length));

		if (!tag_constructed)
		{
			s.append(", ");

			switch (tag)
			{
			case enum_tag::tag_object_identifier:
			{
				append_value_as_hex(s);
				s.append(" => ");

				std::string buffer;

				buffer.append(std::to_string(value[0] / 40));
				buffer.append(".");
				buffer.append(std::to_string(value[0] % 40));
				for (size_t i = 1; i < value.size(); i++)
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

			case enum_tag::tag_boolean:
				if (value[0] == 0)
					s.append("FALSE");
				else if (value[0] == 0xff || value[0] == 1)
					s.append("TRUE");
				else
					s.append("???");
				break;

			case enum_tag::tag_numeric_string:
			case enum_tag::tag_ia5_string:
			case enum_tag::tag_utf8_string:
			case enum_tag::tag_printable_string:
			case enum_tag::tag_t61_string:
			case enum_tag::tag_utc_time:
			case enum_tag::tag_generalized_time:
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
	else if (tag_class == enum_tag_class::class_context_specific)
	{
		if (!is_indefinite)
			s.append("[" + std::to_string(static_cast<int>(tag)) + "]"
				//+ string_array_tag_class[tag_class] + (tag_constructed ? ":CONSTRUCTED" : ":PRIMITIVE")
				+ ", Length " + std::to_string(length));
		else
			s.append("[" + std::to_string(static_cast<int>(tag)) + "]"
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
		s.append(string_array_tag_class[static_cast<int>(tag_class)] + ":");
		tag_constructed ? s.append("CONSTRUCTED:") : s.append("PRIMITIVE:");

		if (!is_indefinite)
			s.append("(TAG " + std::to_string(static_cast<int>(tag)) + ", Length " + std::to_string(length) + ")");
		else
			s.append("(TAG " + std::to_string(static_cast<int>(tag)) + ", Length (indefinite) " + std::to_string(length) + ")");

		if (!tag_constructed)
		{
			s.append(", ");
			append_value_as_hex(s);
		}
	}

	return s;
}

void tlv_parser::tlv::print(tlv* root, unsigned intent) const
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

tlv_parser::tlv::enum_tag tlv_parser::read_tag(const unsigned char* buffer, unsigned int& index, tlv::enum_tag_class& tag_class, bool& tag_constructed)
{
	unsigned long tag = buffer[index++];

	tag_class = static_cast<tlv::enum_tag_class>(tag >> 6);
	tag_constructed = (tag >> 5 & 0x1) > 0;

	tag &= 0x1f;

	if (tag == 0x1f)
	{
		tag = 0;

		unsigned char temp;
		do
		{
			tag <<= 7;
			temp = buffer[index++];
			tag |= temp & 0x7f;
		} while ((temp & 0x80) > 0);
	}

	return static_cast<tlv::enum_tag>(tag);
}

unsigned long tlv_parser::read_length(const unsigned char* buffer, unsigned int& index)
{
	unsigned long len = buffer[index++];
	if (len & 0x80)
	{
		const auto count = len & 0x7f;
		len = 0;
		for (unsigned i = 0; i < count; i++)
		{
			len <<= 8;
			len |= buffer[index++];
		}
	}

	return len;
}

void tlv_parser::parse(tlv* tlv)
{
	const auto childs = parse(&tlv->value[0], tlv->value.size());
	if (!childs.empty())
		tlv->childs = childs;
}

unsigned int tlv_parser::calc_length(unsigned char* buffer)
{
	unsigned int index = 0;

	while (true)
	{
		tlv::enum_tag_class tag_class;
		bool tag_constructed;
		const auto tag = read_tag(buffer, index, tag_class, tag_constructed);
		const auto length = read_length(buffer, index);

		if (tag != tlv::enum_tag::tag_null && length == 0)
		{
			index += calc_length(&buffer[index]);
		}
		else
			index += length;

		if (buffer[index] == 0 && buffer[index + 1] == 0)
		{
			index += 2;
			break;
		}
	}

	return index;
}

std::vector<tlv_parser::tlv*> tlv_parser::parse(unsigned char* buffer, const size_t max_len)
{
	unsigned int index = 0;
	std::vector<tlv*> result;

	tlv* prev_tlv = nullptr;
	do
	{
		tlv::enum_tag_class tag_class;
		bool tag_constructed;
		const auto tag = read_tag(buffer, index, tag_class, tag_constructed);
		auto length = read_length(buffer, index);

		tlv* act_tlv;

		const auto length_indefinite = tag != tlv::enum_tag::tag_null && length == 0;
		if (length_indefinite)
			length = calc_length(&buffer[index]);

		const auto apply_length = length_indefinite ? length - 2 : length;

		if (tag_constructed)
			act_tlv = new tlv(tag, tag_class, tag_constructed, length_indefinite, apply_length, nullptr);
		else
			act_tlv = new tlv(tag, tag_class, tag_constructed, length_indefinite, apply_length, &buffer[index]);

		result.push_back(act_tlv);

		if (tag_constructed)
		{
			auto tlvs = parse(&buffer[index], apply_length);

			for (auto& tlv : tlvs)
				act_tlv->childs.push_back(tlv);
		}

		if (prev_tlv != nullptr)
			prev_tlv->next = act_tlv;

		prev_tlv = act_tlv;

		index += length;

	} while (index < max_len);

	if (index != max_len)
		throw std::exception("index != max_len");

	return result;
}
