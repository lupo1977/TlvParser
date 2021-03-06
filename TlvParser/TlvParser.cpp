// TlvParser.cpp : Diese Datei enthält die Funktion "main". Hier beginnt und endet die Ausführung des Programms.
//

#include "pch.h"
#include <iostream>
#include "tlv_parser.h"

int main(int argc, char ** argv)
{
	if (argc < 2)
	{
		std::cout << "USAGE:" << std::endl;
		std::cout << argv[0] << " filename" << std::endl;

		exit(-1);
	}

	try
	{
		FILE *f = nullptr;
		const auto error_no = fopen_s(&f, argv[1], "rb");
		if (error_no == 0 && f != nullptr)
		{
			fseek(f, 0, SEEK_END);
			const auto file_size = ftell(f);
			fseek(f, 0, SEEK_SET);

			auto buffer = new unsigned char[file_size];
			const auto bytes_read = fread_s(&buffer[0], file_size, sizeof(buffer[0]), file_size, f);
			fclose(f);

			auto root = tlv_parser::parse(buffer, bytes_read);
			if (root.size() > 0)
				root[0]->print();
			else std::cout << "No content?";
		}
		else
		{
			std::cout << "Could not open file '" << argv[1] << "'" << ", error (" << error_no << ")" << std::endl;
		}
	}
	catch (std::exception & ex)
	{
		std::cout << ex.what();
	}
	catch (...)
	{
		std::cout << "Unhandled C++ EXCEPTION!!!";
	}
}
