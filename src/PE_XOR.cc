#include "PE_XOR.h"
#include "file_analysis/Manager.h"

#define NULL_SECTION_START 0x1a
#define NULL_SECTION_END 0x38

using namespace file_analysis;

PE_XOR::PE_XOR(RecordVal* args, File* file)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("PE_XOR"), args, file)
	{
	offset = 0;
	key_found = false;
	}

PE_XOR::~PE_XOR()
	{
	}

bool PE_XOR::DeliverStream(const u_char* data, uint64 len)
	{
	if ( len < 512 )
		return false;
	
	if ( FindKey(data) )
		printf("Key found! '%s'\n", key);

	offset += len;

	return true;
	}

bool PE_XOR::FindKey(const u_char* data)
	{
	if ( offset == 0 )
		{
		key_0 = data[0] ^ 0x4d;
		key_1 = data[1] ^ 0x5a;

		uint64 key_start = 0;

		if ( key_0 == 0 && key_1 == 0 )
			return false;

		// We can our target null section
		for ( uint i = NULL_SECTION_START; i < NULL_SECTION_END; ++i )
			{
			// Is this a place our key could start?
			if ( data[i] == key_0 && data[i+1] == key_1 )
				{
				// Now we scan for a key length
				for ( uint l = ( key_0 == key_1 ) ? 1 : 2; i + l < NULL_SECTION_END; ++l )
					{
					if ( i % l != 0 )
						continue;

					bool possible_key = true;
					for ( uint j = 0; (i + j + l < NULL_SECTION_END) && possible_key; ++j )
						{
						if ( data[i + j] != data[i + l + j] )
							possible_key = false;
						}
					if ( possible_key )
						{
						key = new char[l + 1];
						key[l] = 0;

						memcpy(key, data + i, l);

						return true;						
						}
					}
				}
			}
		}
	return false;
	}

bool PE_XOR::EndOfFile()
	{

	return false;
	}
