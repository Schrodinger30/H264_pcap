# H264_pcap

Python script using the scappy library to read an existing pcap/pcapng file, extract RTP packets carrying H.264 NAL units, reassemble them (including handling FU‑A and STAP‑A), and write out a raw .264 elementary stream.
