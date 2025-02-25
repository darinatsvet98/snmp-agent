import sys
import socket
import struct
import logging
import psutil

# ASN.1 tags
ASN1_SEQUENCE = 0x30
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
ASN1_GET_RESPONSE_PDU = 0xA2
ASN1_OBJECT_IDENTIFIER = 0x06

logging.basicConfig(level=logging.DEBUG)

#custom default port
DEFAULT_PORT = 1161


class SNMPAgent:
  
    oid_mapping = {}  # dictionary to store OID mapping

    @classmethod
    def load_oid_map(cls, file_path='oids.txt'):
        """Load OID mappings from a file to the oid_mapping dictionary."""
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    parts = line.strip().split(',')
                    if len(parts) == 2:
                        cls.oid_mapping[parts[0]] = parts[1]
        except Exception as e:
            logging.error(f"Failed to load OID mappings: {e}")

    @staticmethod
    def encode_length_asn(length):
        """Encode ASN.1 length"""
        if length > 0x7f:
            if length <= 0xff:
                packed_length = 0x81
            elif length <= 0xffff:
                packed_length = 0x82
            elif length <= 0xffffff:
                packed_length = 0x83
            elif length <= 0xffffffff:
                packed_length = 0x84
            else:
                raise Exception('Length is too big!')
            return struct.pack('B', packed_length) + SNMPAgent.encode_int_asn(length)
        return struct.pack('B', length) #short form encoding

    @staticmethod
    def encode_int_asn(value, strip_leading_zeros=True):
        """Encode int in ASN1 format"""
        if abs(value) > 0xffffffffffffffff:
            raise Exception('Int value must be in [0..18446744073709551615]')
        #pack positive or negative int into bytes
        if value < 0:
            if abs(value) <= 0x7f: #hex, in dec: 127
                result = struct.pack('>b', value)
            elif abs(value) <= 0x7fff: # 32767 - max signed int it can hold 16 bit
                result = struct.pack('>h', value)
            elif abs(value) <= 0x7fffffff: # - max signed int it can hold 32 bit
                result = struct.pack('>i', value)
            elif abs(value) <= 0x7fffffffffffffff: #how many bytes are necessary to encode a length
                result = struct.pack('>q', value)
            else:
                raise Exception('Min signed int value')
        else:
            result = struct.pack('>Q', value)
        # optionally strip first null bytes, if all are null - leave one
        result = result.lstrip(b'\x00') if strip_leading_zeros else result
        return result or b'\x00'

    @staticmethod
    def create_tlv(tag, length, value):
        """Create TLV (Tag-Length-Value) structure for the ASN1 encoding"""
        return struct.pack('B', tag) + SNMPAgent.encode_length_asn(length) + value

    @staticmethod
    def create_tv(tag, value):
        """Create TV (Tag-Value) to calculate length from value"""
        return SNMPAgent.create_tlv(tag, len(value), value)

    @staticmethod
    def read_byte(stream):
        """Read byte from stream"""
        read_byte = stream.read(1)
        if not read_byte:
            raise Exception('No more bytes!')
        return ord(read_byte)

    @staticmethod
    def read_int_length(stream, length, signed=False): #read a sequence of bytes 
        """Read int with length"""
        result = 0
        sign = None #positive or negative number
        for _ in range(length):
            value = SNMPAgent.read_byte(stream)
            if sign is None:
                sign = value & 0x80 # decide based on 0x80 if it's postive or neg
            result = (result << 8) + value
        if signed and sign: # negative number
            result = twos_complement(result, 8 * length) # to correctly interpret neg numbers
        return result

    @staticmethod
    def generate_response(version, community, request_id, error_status, error_index, oid_items):
        """Generate SNMP response"""
        response = SNMPAgent.create_tv(
            ASN1_SEQUENCE,
            # add version and community from request
            SNMPAgent.create_tv(ASN1_INTEGER, SNMPAgent.encode_int_asn(version)) +
            SNMPAgent.create_tv(ASN1_OCTET_STRING, community.encode('latin')) +
            # add GetResponse PDU with get response fields
            SNMPAgent.create_tv(
                ASN1_GET_RESPONSE_PDU,
                # add response id, error status and error index
                SNMPAgent.create_tv(ASN1_INTEGER, SNMPAgent.encode_int_asn(request_id)) +
                SNMPAgent.create_tlv(ASN1_INTEGER, 1, SNMPAgent.encode_int_asn(error_status)) +
                SNMPAgent.create_tlv(ASN1_INTEGER, 1, SNMPAgent.encode_int_asn(error_index)) +
                # list oids and their values
                SNMPAgent.create_tv(
                    ASN1_SEQUENCE,
                    b''.join(
                        # add OID and OID value
                        SNMPAgent.create_tv(
                            ASN1_SEQUENCE,
                            SNMPAgent.create_tv(
                                ASN1_OBJECT_IDENTIFIER,
                                oid_key.encode('latin') 
                            ) +
                            oid_value
                        ) for (oid_key, oid_value) in oid_items
                    )
                )
            )
        )
        return response

    @classmethod
    def listen(cls, port=None):
        """Run the server."""
        if port is None:
            port = DEFAULT_PORT

        # Create the server and keep on listening
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
            server_socket.bind(("127.0.0.1", port))
            logging.info(f"SNMP Agent listening on port {port}")

            while True:
                data, addr = server_socket.recvfrom(4096)
                logging.debug(f"Received data from {addr}: {data}")
                logging.debug(f"Hex data: {data.hex()}")

                if True:
                    # try:
                    (
                        version,
                        community,
                        pdu_type,
                        oid,
                        oid_bytes,
                        request_id,
                    ) = cls.parse_snmp_packet(data)
                    version_name = cls.get_snmp_version_name(version)
                    logging.debug(
                        f"Decoded SNMP Request: Version={version_name},"
                        f" Community={community}, PDU Type={pdu_type},"
                        f" OID={oid}"
                    )

                    try:
                        value = cls.get_value(oid)
                    except KeyError as e:
                        value = str(e)

                    response_str = f"Response for {oid}: {value}".encode()

                    # representation of the value to return in response to an SNMP request for a specific OID, must be encoded 
                    response_bytes = (
                        b"\x04"
                        + bytes(bytearray([len(response_str)]))
                        + response_str
                    )

                    response_packet = cls.generate_response(
                        version,
                        community,
                        request_id,
                        error_status=0,
                        error_index=0,
                        oid_items=[("TODO", response_bytes)],
#                        oid_items=[(oid, response_bytes)],
                    )

                    server_socket.sendto(response_packet, addr)

                    logging.debug(
                        f"Encoded SNMP Response for OID {oid}: {value}"
                    )
                # except Exception as e:
                #     logging.error(f"Error processing packet: {e}")

    @classmethod
    # reading and breaking down the raw bytes sent from an SNMP manager from the GetRequest
    def parse_snmp_packet(cls, packet):
        # first INTEGER is the version
        version = packet[3]

        # first string is the community
        community_end_index = packet.find(b"\xa0")
        community = packet[6:community_end_index].decode("utf-8")
        pdu_type = format(packet[community_end_index], "02x")

        # REQUEST ID is the next integer (\x02).
        length_index = (
            packet[community_end_index:].find(b"\x02")
            + community_end_index
            + 1
        )

        length = packet[length_index]
        try:
            from StringIO import StringIO
        except ImportError:
            from io import StringIO

        request_id_bytes = packet[
            length_index + 1 : length_index + 1 + length * 8
        ]

        # request_id_bytes is a valid integer which must be converted to SNMP
        request_id = cls.read_int_length(
            StringIO(request_id_bytes.decode("latin")), length
        )

        oid_start_index = packet.find(b"\x06", community_end_index) + 2
        oid_length = packet[oid_start_index - 1]
        oid_bytes = packet[oid_start_index : oid_start_index + oid_length]

        logging.debug(f"oid_bytes: {oid_bytes.hex()}")

        oid = cls.decode_oid(oid_bytes)

        return version, community, pdu_type, oid, oid_bytes, request_id

    @staticmethod
    def decode_oid(oid_bytes):
        oid = []
        index = 0

        if oid_bytes:
            first_byte = oid_bytes[0]
            oid.append(1)  # 1-st part of OID is always 1
            oid.append(
                first_byte - 40
            )  # subtract 40 from the 1-st byte to get the 2-nd part of OID
            index += 1

        while index < len(oid_bytes):
            byte = oid_bytes[index]
            if byte >= 128:
                next_byte = 0
                while byte >= 128:
                    next_byte = (next_byte << 7) | (byte & 0x7F)
                    index += 1
                    byte = oid_bytes[index]
                next_byte = (next_byte << 7) | byte
                oid.append(next_byte)
            else:
                oid.append(byte)
            index += 1

        # OID as string
        return ".".join(str(num) for num in oid)

    @staticmethod
    def get_snmp_version_name(version):
        """Convert SNMP version to its name."""
        if version == 0:
            return "(SNMPv1)"
        elif version == 1:
            return "(SNMPv2c)"
        elif version == 3:
            return "(SNMPv3)"
        else:
            return "Unknown"

    @classmethod
    def get_value(cls, oid):
        """Return the value in response to the OID."""
        if oid in cls.oid_mapping:
            response_type = cls.oid_mapping[oid]
            if response_type == 'MemoryAvailable':
                return str(psutil.virtual_memory().available)
            elif response_type == 'SystemCPUTime':
                return str(psutil.cpu_times_percent().system)
            elif response_type == 'DiskUsage':
                return str(psutil.disk_usage("/").free)
            else:
                raise KeyError(f"Response type '{response_type}' not implemented")
        else:
            raise KeyError("Unknown OID")

if __name__ == "__main__":
    from sys import argv

    # load OID mappings
    SNMPAgent.load_oid_map('oids.txt')

    port = None if len(argv) < 2 else argv[1]
    SNMPAgent.listen(port)
