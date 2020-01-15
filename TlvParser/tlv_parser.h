#pragma once
#include <vector>
#include <string>

class tlv_parser
{
public:
	class tlv
	{
	public:

		enum class enum_tag_class
		{
			class_universal = 0,
			class_application = 1,
			class_context_specific = 2,
			class_private = 3
		};

		enum class enum_tag
		{
			tag_ber = 0,
			tag_boolean = 1,
			tag_integer = 2,
			tag_bit_string = 3,
			tag_octet_string = 4,
			tag_null = 5,
			tag_object_identifier = 6,
			tag_object_descriptor = 7,
			tag_external = 8,
			tag_real = 9,
			tag_enumerated = 10,
			tag_embedded_pdv = 11,
			tag_utf8_string = 12,
			tag_relative_oid = 13,
			tag_sequence = 16,
			tag_set = 17,
			tag_numeric_string = 18,
			tag_printable_string = 19,
			tag_t61_string = 20,
			tag_videotex_string = 21,
			tag_ia5_string = 22,
			tag_utc_time = 23,
			tag_generalized_time = 24,
			tag_graphic_string = 25,
			tag_visible_string = 26,
			tag_general_string = 27,
			tag_universal_string = 28,
			tag_character_string = 29,
			tag_bmp_string = 30,

			// Are the following tags correct?
			tag_date = 31,
			tag_time_of_day = 32,
			tag_date_time = 33,
			tag_duration = 34,
			tag_oid_iri = 35,
			tag_relative_oid_iri = 36,
		};

		tlv* next{};
		std::vector<tlv*> childs{};

		enum_tag_class tag_class;
		bool tag_constructed;

		enum_tag tag;
		bool is_indefinite;
		unsigned long length;
		std::vector<unsigned char> value{};

		tlv(enum_tag t, enum_tag_class t_class, bool t_constructed, bool indefinite, unsigned long l, unsigned char* buffer);
		void append_value_as_hex(std::string& s);
		std::string to_string(unsigned intent);

		void print(tlv* root, unsigned intent) const;
		void print();
	};

private:
	static tlv::enum_tag read_tag(const unsigned char* buffer, unsigned int& index, tlv::enum_tag_class& tag_class, bool& tag_constructed);
	static unsigned long read_length(const unsigned char* buffer, unsigned int& index);
	static unsigned int calc_length(unsigned char* buffer);
	static void parse(tlv* tlv);

public:
	static std::vector<tlv*> parse(unsigned char* buffer, size_t max_len);
};
