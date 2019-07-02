#pragma once
#include <vector>

class tlv_parser
{
public:
	class tlv
	{
	public:

		enum enum_tag_class
		{
			universal = 0,
			application = 1,
			context_specific = 2,
			Private = 3
		};

		enum enum_tag
		{
			EOC = 0,
			BOOLEAN = 1,
			INTEGER = 2,
			BIT_STRING = 3,
			OCTET_STRING = 4,
			NULL_ = 5,
			OBJECT_IDENTIFIER = 6,
			OBJECT_DESCRIPTOR = 7,
			EXTERNAL = 8,
			REAL = 9,
			ENUMERATED = 10,
			EMBEDDED_PDV = 11,
			UTF8String = 12,
			RELATIVE_OID = 13,
			TIME = 14,
			Reserved = 15,
			SEQUENCE = 16,
			SET = 17,
			NumericString = 18,
			PrintableString = 19,
			T61String = 20,
			VideotexString = 21,
			IA5String = 22,
			UTCTime = 23,
			GeneralizedTime = 24,
			GraphicString = 25,
			VisibleString = 26,
			GeneralString = 27,
			UniversalString = 28,
			CHARACTER_STRING = 29,
			BMPString = 30,
			DATE = 31,
			TIME_OF_DAY = 32,
			DATE_TIME = 33,
			DURATION = 34,
			OID_IRI = 35,
			RELATIVE_OID_IRI = 36,
		};

		tlv * next{};
		std::vector<tlv *> childs{};

		enum_tag_class tag_class;
		bool tag_constructed;

		enum_tag tag;
		unsigned long length;
		std::vector<unsigned char> value{};

		tlv(enum_tag t, enum_tag_class t_class, bool t_constructed, const unsigned long l, unsigned char * buffer);
		void append_value_as_hex(std::string& s);
		std::string to_string(unsigned intent);

		void print(tlv * root, unsigned intent) const;
		void print();
	};

private:
	static tlv::enum_tag read_tag(const unsigned char * buffer, unsigned int & index, tlv::enum_tag_class & tag_class, bool & tag_constructed);
	static unsigned long read_length(const unsigned char * buffer, unsigned int & index);
	static void parse(tlv * tlv);

public:
	static std::vector<tlv *> parse(unsigned char * buffer, const unsigned int max_len);
};
