# snmp-agent
oid.txt and python agent should be in the same folder

How to run locally on MacOS:
1. check for python
2. open two terminals
    - terminal 1 for agent: "python3 iii-snmp.py"
    - terminal 2 for manager: snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.2021.4.6.0

The iii-snmp Agent code includes a mechanism for reading Object Identifiers (OIDs) and their corresponding types or mappings from an external text file (`oids.txt`). 
In my case I have defined three OIDs:
    1.3.6.1.4.1.2021.4.6.0,MemoryAvailable
    1.3.6.1.4.1.2021.11.10.0,SystemCPUTime
    1.3.6.1.4.1.2021.9.1.7.1,DiskUsage

#####################
Functions used in the agent and their functionality:

#load_oid_mapping: store oid mappings

#encode_length_asn: If the length is greater than 127, it needs to determine how many bytes are needed to represent the length. returns the packed length, which is a byte string that can be part of an ASN.1 encoded piece of data. This byte string tells any decoder how long the following data is

#encode_int_asn: encodes an integer value into a sequence of bytes; handles postive, 0, negative values; strips out any leading zero bytes from the result ; prepares an integer to be correctly formatted as part of an ASN.1 encoded data structure

#create_tlv: tag: A single byte that specifies the type of the value (like integer, string, etc.).
length: The size of the value in bytes.
value: The actual data to encode.

#create_tv: creates a TV (Tag-Value) structure where the length is not provided but is calculated from the value directly

#read_byte: reads a single byte from a stream

#read_int_len: reads an integer of a specified length from a binary stream, which can be either signed or unsigned;
It loops exactly length times, each time reading one byte from the stream; For each byte read, it shifts result 8 bits to the left; returns the constructed integer


#generate_response: begins by creating an ASN.1 sequence then it adds the version and community +  constructs a GetResponse Protocol Data Unit (PDU) + Request ID, Error Status, and Error Index
encodes each part and returns complete message

#listen: listening for incoming SNMP requests and responding to them;
port check; create socket;
loop incoming packets: receives hexadecimal representation of data, parses packet for SNMP version, community string, PDU type, OID, and request ID; fetch the value associated with the requested OID;
Encodes the response string;
prepares it for sending by prefixing it with its type (0x04 for octet string)


#parse_snmp_packet: - Read from manager;  
- searching for the byte 0xA0 (which marks the beginning of the SNMP PDU); 
- finds the position of the request ID by searching for the byte 0x02 (indicating an INTEGER type in ASN.1); calculates the length of the request ID and then extracts the corresponding bytes; finds the starting position of the OID by looking for the byte 0x06 and extracts the OID's length and bytes, then decodes them into a dot-separated string representing the OID

#decode_oid: 1.3 corresponds to 0x2b, which is 43 in decimal; since the first arc is always 1, subtracting 40 gives the second arc; processing all bytes, the method joins the numerical components in the oid list with dots (.)

#get_snmp_version_name: translates the numerical representation of an SNMP version to its corresponding name as a string

#get_value: respond to SNMP Get requests by providing the current value of a specified OID (Object Identifier)

