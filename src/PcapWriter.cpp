#include <stdexcept>
#include <sys/time.h>
#include <cstring>
#include <arpa/inet.h>

#include "PcapWriter.hpp"

namespace DDoSD {

PcapWriter::PcapWriter(const std::string& pcap_filename, int linktype, int snaplen)
    : mLinkType(linktype) {

    if (linktype != DLT_EN10MB && linktype != DLT_C_HDLC && linktype != 12)
        throw std::runtime_error("unsupported link layer type (code " + std::to_string(linktype) + ")");

    mPcapHandler = pcap_open_dead(linktype, snaplen);
    mPcapDumper = pcap_dump_open(mPcapHandler, pcap_filename.c_str());
    if (mPcapDumper == nullptr)
        throw std::runtime_error("could not create pcap file '" + pcap_filename + "'");

    gettimeofday(&mLastTs, nullptr);
}

PcapWriter::~PcapWriter() {
    pcap_dump_close(mPcapDumper);
    pcap_close(mPcapHandler);
}

void PcapWriter::writePacket(const PcapPacket& packet) {
    pcap_dump(reinterpret_cast<u_char*>(mPcapDumper), packet.metadata, packet.data);
}

void PcapWriter::writePacket(uint32_t src_ipv4, uint32_t dst_ipv4, struct timeval ts, void* payload, uint16_t payload_len) {
    uint16_t l2_header_length;
    if (mLinkType == DLT_EN10MB)
        l2_header_length = 14;
    else if (mLinkType == DLT_C_HDLC)
        l2_header_length = 4;
    else
        l2_header_length = 0;

    struct pcap_pkthdr metadata;
    metadata.ts = ts;
    metadata.caplen = l2_header_length + 20 + payload_len;
    if (payload_len % 2 == 1)
        ++metadata.caplen;
    metadata.len = metadata.caplen;

    u_char data[metadata.caplen];
    if (mLinkType == DLT_EN10MB) {
        memcpy(data, "\x00\x00\x00\x00\x00\x00", 6);
        memcpy(data + 6, "\x00\x00\x00\x00\x00\x00", 6);
        memcpy(data + 12, "\x08\x00", 2);
    }
    else if (mLinkType == DLT_C_HDLC)
        memcpy(data, "\x00\x00\x08\x00", 4);

    src_ipv4 = htonl(src_ipv4);
    dst_ipv4 = htonl(dst_ipv4);
    const uint16_t total_len = htons(20 + payload_len);

    memcpy(data + 14, "\x45\x00", 2);
    memcpy(data + 16, &total_len, 2);
    memcpy(data + 18, "\x00\x00\x00\x00", 4);
    memcpy(data + 22, "\xff\xfd\x00\x00", 4);
    memcpy(data + 26, &src_ipv4, 4);
    memcpy(data + 30, &dst_ipv4, 4);

    memcpy(data + 34, payload, payload_len);

    if (payload_len % 2 == 1) {
        memcpy(data + 34 + payload_len, "\x00", 1);
    }

    pcap_dump(reinterpret_cast<u_char*>(mPcapDumper), &metadata, data);

    mLastTs = ts;
}

void PcapWriter::writePacket(uint32_t src_ipv4, uint32_t dst_ipv4, void* payload, uint16_t payload_len) {
    writePacket(src_ipv4, dst_ipv4, mLastTs, payload, payload_len);
}

}
