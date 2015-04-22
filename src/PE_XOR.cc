#include "BroString.h"

#include "PE_XOR.h"
#include "file_analysis/Manager.h"

#define NULL_SECTION_START 0x1a
#define NULL_SECTION_END 0x38
#define MAX_KEY_LEN 30

using namespace file_analysis;

PE_XOR::PE_XOR(RecordVal* args, File* file)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("PE_XOR"), args, file)
	{
	offset = 0;
	key_found = false;
	skip = false;
	}

PE_XOR::~PE_XOR()
	{
	}

bool PE_XOR::DeliverStream(const u_char* data, uint64 len)
	{
	if ( skip )
		return true;

	if ( ! key_found && len < 512 )
		{
		// This probably shouln't happen.
		skip = true;
		return true;
		}
	
	if ( ! key_found )
		{
		key_found = FindKey(data);
		if ( key_found )
			{
			file_id = file_mgr->HashHandle(GetFile()->GetID());

			val_list* vl = new val_list();
			vl->append(GetFile()->GetVal()->Ref());
			vl->append(new StringVal(new BroString((const u_char *)key, key_len, 1)));
			vl->append(new StringVal(file_id));
			mgr.QueueEvent(pe_xor_found, vl);
			}
		else
			{
			skip = true;
			return true;
			}
		}

	if ( key_found )
		{
		unsigned char* plaintext = new unsigned char[len];
		for ( uint64 i = 0; i < len; ++i )
			plaintext[i] = data[i] ^ key[(i + offset) % key_len];

		file_mgr->DataIn(plaintext, len, file_id, string(fmt("XOR decrypted from ")) + GetFile()->GetID());
		}

	else
		{
		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		mgr.QueueEvent(pe_xor_not_found, vl);
		}
	

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
				for ( uint l = ( key_0 == key_1 ) ? 1 : 2; ( i + l < NULL_SECTION_END ) && l < MAX_KEY_LEN; ++l )
					{
					if ( i % l != 0 )
						continue;

					bool possible_key = true;
					for ( uint j = 0; (i + j + l < NULL_SECTION_END) && (j < 2 * l) && possible_key; ++j )
						{
						if ( data[i + j] != data[i + l + j] )
							possible_key = false;
						}
					if ( possible_key )
						{
						key = new char[l + 1];
						key[l] = 0;
						key_len = l;

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
	file_mgr->EndOfFile("test_file");
	return false;
	}
