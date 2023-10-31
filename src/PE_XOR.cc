// Copyright 2017-2021, Corelight, Inc. All rights reserved.

#include "PE_XOR.h"
#include "zeek/file_analysis/Manager.h"

#define NULL_SECTION_START 0x1a
#define NULL_SECTION_END 0x38
#define MAX_KEY_LEN 30

namespace zeek::file_analysis::detail {

PE_XOR::PE_XOR(RecordValPtr args, file_analysis::File* file)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("PE_XOR"), std::move(args), file)
	{
	offset = 0;
	key_found = false;
	skip = false;
	}

PE_XOR::~PE_XOR()
	{
	}

bool PE_XOR::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( skip )
		return true;

	if ( ! key_found && len < 512 )
		{
		// This probably shouldn't happen.
		skip = true;
		return true;
		}

	if ( ! key_found )
		{
		key_found = FindKey(data);
		if ( key_found )
			{
			file_id = file_mgr->HashHandle(GetFile()->GetID());

			zeek::event_mgr.Enqueue(pe_xor_found,
			                        GetFile()->ToVal(),
			                        zeek::make_intrusive<zeek::StringVal>(key_len, reinterpret_cast<const char*>(key)),
			                        zeek::make_intrusive<zeek::StringVal>(file_id));
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
		for ( uint64_t i = 0; i < len; ++i )
			plaintext[i] = data[i] ^ key[(i + offset) % key_len];

		file_mgr->DataIn(plaintext, len, file_id, std::string(zeek::util::fmt("XOR decrypted from ")) + GetFile()->GetID());
		}

	else
		{
		zeek::event_mgr.Enqueue(pe_xor_not_found, GetFile()->ToVal());
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

		// The number of times we must see the key repeated to
		// confirm it depends on the length of the key for short keys.
		char key_reqs[3] = {5, 4, 3};

		if ( key_0 == 0 && key_1 == 0 )
			return false;

		// We can our target null section
		for ( uint i = NULL_SECTION_START; i < NULL_SECTION_END; ++i )
			{
			// Is this a place our key could start?
			if ( data[i] == key_0 && data[i+1] == key_1 )
				{
				// Now we scan for a key length
				// If our key_0 == key_1, try a key length of 1. Otherwise, start at 2.
				for ( uint l = ( key_0 == key_1 ) ? 1 : 2;
				      // Keep going until we get to NULL_SECTION END, or we hit the max key length
				      ( i + l < NULL_SECTION_END ) && l < MAX_KEY_LEN;
				      ++l )
					{
					// Our key length doesn't line up with our start
					if ( i % l != 0 )
						continue;

					bool possible_key = true;

					// Key length | Number of times we need to see the whole key to confirm
					// -----------|--------------------------------------------------------
					//     1      |   5
					//     2      |   4
					//     3      |   3
					//     4+     |   2
					uint8_t required_key_iterations = l < 4 ? key_reqs[l - 1] : 2;

					// Now we check to see if data[j] == data[j + l]
					for ( uint j = 0; 
					      // Keep going until NULL_SECTION_END, we have excluded this as a possible key,
					      // or, we repeated it the requisite number of times (depends on the length).
					      (i + j + l < NULL_SECTION_END) && (j < required_key_iterations * l) && possible_key; 
					      ++j )
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
	file_mgr->EndOfFile(file_id);
	return false;
	}

} // namespace zeek::file_analysis::detail
