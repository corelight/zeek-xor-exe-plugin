# This tests a XOR-encoded EXE downloaded from the Nuclear Exploit Kit.
# See: http://malware-traffic-analysis.net/2015/04/09/index.html

# @TEST-EXEC: bro -r $TRACES/2015-04-09-Nuclear-EK-traffic.pcap %INPUT > output
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff pe.log
# @TEST-EXEC: btest-diff notice.log

@load Broala/PE_XOR
