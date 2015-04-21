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
		printf("Key found!\n");
	
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

		for ( uint i = NULL_SECTION_START; i < NULL_SECTION_END; ++i )
			{
			if ( data[i] == key_0 && data[i+1] == key_1 )
				{
				if ( key_start == 0 )
					// We saw the key here.
					key_start = i;
				else
					{
					// And now we saw it again.
					bool possible_key_found = true;
					uint64 key_offset = i - key_start;
					for ( uint j = key_start; j < i && possible_key_found; ++j )
						{
						if ( data[j] != data[j + key_offset] )
							possible_key_found = false;
						}
					if ( possible_key_found )
						{
						key_len = key_offset;

						key = new char[key_len + 1];
						key[key_len] = 0;

						memcpy(key, data + key_start, key_len);

						printf("Found key: %s @%x\n", key, i);
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
