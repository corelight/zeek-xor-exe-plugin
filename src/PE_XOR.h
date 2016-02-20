// Copyright 2015, Broala LLC. All rights reserved.

#ifndef FILE_ANALYSIS_PE_XOR_H
#define FILE_ANALYSIS_PE_XOR_H

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

	virtual bool DeliverStream(const u_char* data, uint64 len);

	virtual bool EndOfFile();

protected:
	PE_XOR(RecordVal* args, File* file);

	bool FindKey(const u_char* data);

private:
	uint8 key_0;
	uint8 key_1;

	uint64 offset;

	char* key;
	uint8 key_len;

	bool key_found;
	bool skip;

	string file_id;
};

} // namespace file_analysis

#endif
