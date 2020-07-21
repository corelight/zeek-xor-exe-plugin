// Copyright 2017, Corelight, Inc. All rights reserved.

#pragma once

#include "Val.h"
#include "file_analysis/File.h"
#include "file_analysis/Analyzer.h"

#include "pe_xor.bif.h"

namespace file_analysis {

/**
 * Analyze XOR-encrypted Portable Executable files
 */
class PE_XOR : public file_analysis::Analyzer {
public:
	~PE_XOR();

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ return new PE_XOR(args, file); }

	virtual bool DeliverStream(const u_char* data, uint64_t len);

	virtual bool EndOfFile();

protected:
	PE_XOR(RecordVal* args, File* file);

	bool FindKey(const u_char* data);

private:
	uint8_t key_0;
	uint8_t key_1;

	uint64_t offset;

	char* key;
	uint8_t key_len;

	bool key_found;
	bool skip;

	string file_id;
};

} // namespace file_analysis

