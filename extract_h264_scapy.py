import sys
import os
import argparse
from scapy.all import rdpcap, UDP

MAX_JITTER_SIZE = 50
SEQ_MOD = 1 << 16  # 65536


def parse_args():
    p = argparse.ArgumentParser(
        description="Extract H.264 over RTP from a pcap into a .264 file (Scapy-based, wrap‑aware)"
    )
    p.add_argument("input_pcap", help="Input pcap or pcapng file")
    p.add_argument("output_h264", help="Output raw H.264 elementary stream")
    return p.parse_args()


def write_nal(payload, out_f):
    out_f.write(b"\x00\x00\x00\x01" + payload)


def process_fragments(fragments, out_f):
    # Reconstruct original NAL header
    fu_ind = fragments[0][0]
    fu_hdr = fragments[0][1]
    nal_hdr = bytes([(fu_ind & 0xE0) | (fu_hdr & 0x1F)])
    out_f.write(b"\x00\x00\x00\x01" + nal_hdr)
    for frag in fragments:
        out_f.write(frag[2:])


def extended_seq(seq, base):
    """
    Map a 16-bit sequence number into the nearest wrap-adjusted value
    relative to base (a possibly extended sequence).
    """
    # Compute number of wraps to consider: base//SEQ_MOD ± 1
    k = base // SEQ_MOD
    candidates = [(k + offset) * SEQ_MOD + seq for offset in (-1, 0, 1)]
    # Choose candidate closest to base
    return min(candidates, key=lambda x: abs(x - base))


def extract(input_pcap, output_h264):
    packets = rdpcap(input_pcap)
    jitter_buf = []  # list of tuples (extended_seq, seq16, payload)
    fu_buffer = None
    base_ext_seq = None

    with open(output_h264, "wb") as out_f:
        for pkt in packets:
            if UDP not in pkt:
                continue
            data = bytes(pkt[UDP].payload)
            # Basic RTP check
            if len(data) <= 12 or (data[0] & 0xC0) != 0x80:
                continue

            seq16 = int.from_bytes(data[2:4], "big")
            payload = data[12:]

            # Determine extended sequence
            if base_ext_seq is None:
                ext = seq16  # first packet sets baseline
            else:
                ext = extended_seq(seq16, base_ext_seq)
            if base_ext_seq is None or ext < base_ext_seq:
                base_ext_seq = ext

            jitter_buf.append((ext, seq16, payload))

            if len(jitter_buf) > MAX_JITTER_SIZE:
                # Sort by extended sequence, pop lowest
                jitter_buf.sort(key=lambda x: x[0])
                _, seq16_popped, pl = jitter_buf.pop(0)
                nal_type = pl[0] & 0x1F

                if 1 <= nal_type <= 23:
                    fu_buffer = None
                    write_nal(pl, out_f)

                elif nal_type == 28:
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
                    # STAP-A aggregation
                    offset = 1
                    while offset + 2 <= len(pl):
                        size = int.from_bytes(pl[offset : offset + 2], "big")
                        offset += 2
                        write_nal(pl[offset : offset + size], out_f)
                        offset += size
                else:
                    fu_buffer = None

        # Flush remaining buffer
        for _, seq16, pl in sorted(
            jitter_buf, key=lambda x: extended_seq(x[1], base_ext_seq)
        ):
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
                    size = int.from_bytes(pl[offset : offset + 2], "big")
                    offset += 2
                    write_nal(pl[offset : offset + size], out_f)
                    offset += size

    print(f"Wrote H.264 stream to {output_h264}")


if __name__ == "__main__":
    args = parse_args()
    if not os.path.isfile(args.input_pcap):
        print("Error: input file not found:", args.input_pcap, file=sys.stderr)
        sys.exit(1)
    extract(args.input_pcap, args.output_h264)
