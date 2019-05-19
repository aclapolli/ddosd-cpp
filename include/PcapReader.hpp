#pragma once

#include <pcap.h>
#include <string>
#include <cstdint>

#define ETHERTYPE_DDOSD 0x6605

namespace DDoSD {

struct ddosd_t {
    uint32_t pkt_num;
    uint32_t src_entropy;
    uint32_t src_ewma;
    uint32_t src_ewmmd;
    uint32_t dst_entropy;
    uint32_t dst_ewma;
    uint32_t dst_ewmmd;
    uint8_t alarm;
    uint16_t ether_type;
};

struct PcapPacket {
    struct pcap_pkthdr* metadata;
    const u_char* data;
};

class PcapReader {
    public:
        PcapReader(const std::string& pcap_filename);

        PcapReader(const PcapReader&) = delete;
        PcapReader& operator=(const PcapReader&) = delete;

        ~PcapReader();

        int nextPacket(PcapPacket& pcap_packet);

        uint32_t srcIpv4(const PcapPacket& pcap_packet) const;
        uint32_t dstIpv4(const PcapPacket& pcap_packet) const;

        uint32_t ddosdPktNum(const PcapPacket& pcap_packet) const;
        uint32_t ddosdSrcEntropy(const PcapPacket& pcap_packet) const;
        uint32_t ddosdSrcEwma(const PcapPacket& pcap_packet) const;
        uint32_t ddosdSrcEwmmd(const PcapPacket& pcap_packet) const;
        uint32_t ddosdDstEntropy(const PcapPacket& pcap_packet) const;
        uint32_t ddosdDstEwma(const PcapPacket& pcap_packet) const;
        uint32_t ddosdDstEwmmd(const PcapPacket& pcap_packet) const;
        uint8_t ddosdAlarm(const PcapPacket& pcap_packet) const;
        uint16_t ddosdEtherType(const PcapPacket& pcap_packet) const;

    private:
        pcap_t* mPcapHandler;
        int mLinkType;

        std::size_t l2HeaderLength() const;
        uint16_t l2EtherType(const PcapPacket& pcap_packet) const;
};

}
