# Import packages
import sys
import os
import argparse
from scapy.all import rdpcap, UDP
from bitstring import BitArray

MAX_JITTER_SIZE = 50


def parse_args():
    p = argparse.ArgumentParser(
        description="Extract H.264 over RTP from a pcap into a .264 file"
    )
    p.add_argument("input_pcap", help="Input pcap(ng) file")
    p.add_argument("output_h264", help="Output raw H.264")
    return p.parse_args()


def write_nal(payload_bytes, out_f):
    """Write a single NAL unit with start code."""
    out_f.write(b"\x00\x00\x00\x01" + payload_bytes)


def process_fragments(frag_buf, out_f):
    """Reassemble FU-A fragments in frag_buf and write NAL."""
    # first byte: FU indicator, second: FU header
    fu_ind = frag_buf[0][0]
    fu_hdr = frag_buf[0][1]
    nal_hdr = bytes([(fu_ind & 0xE0) | (fu_hdr & 0x1F)])
    out_f.write(b"\x00\x00\x00\x01" + nal_hdr)
    # each fragment payload minus first two bytes
    for frag in frag_buf:
        out_f.write(frag[2:])


def extract(input_pcap, output_h264):
    packets = rdpcap(input_pcap)
    # jitter buffer: list of (seq, payload_bytes)
    jitter = []
    fu_buffer = None

    with open(output_h264, "wb") as out_f:
        for pkt in packets:
            # Look for UDP port carrying RTP; you may need to adjust ports
            if UDP not in pkt:
                continue
            udp = pkt[UDP]
            # Basic RTP detection: payload length > 12 and first two bits == 10
            data = bytes(udp.payload)
            if len(data) <= 12 or (data[0] & 0xC0) != 0x80:
                continue

            # Parse RTP header
            seq = int.from_bytes(data[2:4], "big")
            payload = data[12:]

            # Jitter buffer insert
            jitter.append((seq, payload))
            if len(jitter) > MAX_JITTER_SIZE:
                # simple reorder: sort by seq (wrap at 65535)
                jitter.sort(key=lambda x: x[0])
                s, pl = jitter.pop(0)
                nal_type = pl[0] & 0x1F

                if 1 <= nal_type <= 23:
                    fu_buffer = None
                    write_nal(pl, out_f)

                elif nal_type == 28:
                    # FU-A
                    start = (pl[1] & 0x80) != 0
                    end = (pl[1] & 0x40) != 0

                    if start:
                        fu_buffer = [pl]
                    elif fu_buffer is None:
                        continue
                    else:
                        fu_buffer.append(pl)

                    if end and fu_buffer:
                        process_fragments(fu_buffer, out_f)
                        fu_buffer = None

                elif nal_type == 24:
                    # STAP-A: skip first byte, then lengths
                    offset = 1
                    while offset + 2 <= len(pl):
                        nal_sz = int.from_bytes(pl[offset : offset + 2], "big")
                        offset += 2
                        write_nal(pl[offset : offset + nal_sz], out_f)
                        offset += nal_sz

                else:
                    fu_buffer = None

        # Flush any remaining in jitter
        for s, pl in sorted(jitter, key=lambda x: x[0]):
            nal_type = pl[0] & 0x1F
            if 1 <= nal_type <= 23:
                write_nal(pl, out_f)
            elif nal_type == 28 and fu_buffer:
                fu_buffer.append(pl)
                process_fragments(fu_buffer, out_f)
                fu_buffer = None
            elif nal_type == 24:
                offset = 1
                while offset + 2 <= len(pl):
                    nal_sz = int.from_bytes(pl[offset : offset + 2], "big")
                    offset += 2
                    write_nal(pl[offset : offset + nal_sz], out_f)
                    offset += nal_sz

    print(f"Wrote H.264 stream to {output_h264}")


if __name__ == "__main__":
    args = parse_args()
    if not os.path.isfile(args.input_pcap):
        print("Input PCAP not found.", file=sys.stderr)
        sys.exit(1)
    extract(args.input_pcap, args.output_h264)
