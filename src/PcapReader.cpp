#include "PcapReader.hpp"

#include <stdexcept>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

namespace DDoSD {

PcapReader::PcapReader(const std::string& pcap_filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    mPcapHandler = pcap_open_offline(pcap_filename.c_str(), errbuf);
    if (mPcapHandler == nullptr)
        throw std::runtime_error("could not open pcap file '" + pcap_filename + "'");
    mLinkType = pcap_datalink(mPcapHandler);
}

PcapReader::~PcapReader() {
    pcap_close(mPcapHandler);
}

int PcapReader::nextPacket(PcapPacket& pcap_packet) {
    const int ret = pcap_next_ex(mPcapHandler, &pcap_packet.metadata, &pcap_packet.data);
    if (ret == -1)
        throw std::runtime_error(pcap_geterr(mPcapHandler));
    return ret;
}

std::size_t PcapReader::l2HeaderLength() const {
    uint16_t l2_header_length = 0;
    if (mLinkType == DLT_EN10MB)
        l2_header_length = 14;
    else if (mLinkType == DLT_C_HDLC)
        l2_header_length = 4;
    else if (mLinkType == 12)
        l2_header_length = 0;
    else
        throw std::runtime_error("unsupported link type " + std::to_string(mLinkType));

    return l2_header_length;
}

uint16_t PcapReader::l2EtherType(const PcapPacket& pcap_packet) const {
    uint16_t ether_type = 0;
    if (mLinkType == DLT_EN10MB)
        ether_type = ntohs(*reinterpret_cast<const uint16_t*>(pcap_packet.data + 12));
    else if (mLinkType == DLT_C_HDLC)
        ether_type = ntohs(*reinterpret_cast<const uint16_t*>(pcap_packet.data + 2));
    else if (mLinkType == 12)
        ether_type = ETHERTYPE_IP;
    else
        throw std::runtime_error("unsupported link type " + std::to_string(mLinkType));

    return ether_type;
}

uint32_t PcapReader::srcIpv4(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_IP)
        throw std::runtime_error("could not extract source IPv4 from packet");
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(pcap_packet.data + l2HeaderLength());
    return ntohl(ip_header->ip_src.s_addr);
}

uint32_t PcapReader::dstIpv4(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_IP)
        throw std::runtime_error("could not extract source IPv4 from packet");
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(pcap_packet.data + l2HeaderLength());
    return ntohl(ip_header->ip_dst.s_addr);
}

uint32_t PcapReader::ddosdPktNum(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_DDOSD)
        throw std::runtime_error("could not extract DDoSD information from packet");
    const struct ddosd_t* ddosd_header = reinterpret_cast<const struct ddosd_t*>(pcap_packet.data + l2HeaderLength());
    return ntohl(ddosd_header->pkt_num);
}

uint32_t PcapReader::ddosdSrcEntropy(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_DDOSD)
        throw std::runtime_error("could not extract DDoSD information from packet");
    const struct ddosd_t* ddosd_header = reinterpret_cast<const struct ddosd_t*>(pcap_packet.data + l2HeaderLength());
    return ntohl(ddosd_header->src_entropy);
}

uint32_t PcapReader::ddosdSrcEwma(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_DDOSD)
        throw std::runtime_error("could not extract DDoSD information from packet");
    const struct ddosd_t* ddosd_header = reinterpret_cast<const struct ddosd_t*>(pcap_packet.data + l2HeaderLength());
    return ntohl(ddosd_header->src_ewma);
}

uint32_t PcapReader::ddosdSrcEwmmd(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_DDOSD)
        throw std::runtime_error("could not extract DDoSD information from packet");
    const struct ddosd_t* ddosd_header = reinterpret_cast<const struct ddosd_t*>(pcap_packet.data + l2HeaderLength());
    return ntohl(ddosd_header->src_ewmmd);
}

uint32_t PcapReader::ddosdDstEntropy(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_DDOSD)
        throw std::runtime_error("could not extract DDoSD information from packet");
    const struct ddosd_t* ddosd_header = reinterpret_cast<const struct ddosd_t*>(pcap_packet.data + l2HeaderLength());
    return ntohl(ddosd_header->dst_entropy);
}

uint32_t PcapReader::ddosdDstEwma(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_DDOSD)
        throw std::runtime_error("could not extract DDoSD information from packet");
    const struct ddosd_t* ddosd_header = reinterpret_cast<const struct ddosd_t*>(pcap_packet.data + l2HeaderLength());
    return ntohl(ddosd_header->dst_ewma);
}

uint32_t PcapReader::ddosdDstEwmmd(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_DDOSD)
        throw std::runtime_error("could not extract DDoSD information from packet");
    const struct ddosd_t* ddosd_header = reinterpret_cast<const struct ddosd_t*>(pcap_packet.data + l2HeaderLength());
    return ntohl(ddosd_header->dst_ewmmd);
}

uint8_t PcapReader::ddosdAlarm(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_DDOSD)
        throw std::runtime_error("could not extract DDoSD information from packet");
    const struct ddosd_t* ddosd_header = reinterpret_cast<const struct ddosd_t*>(pcap_packet.data + l2HeaderLength());
    return ddosd_header->alarm;
}

uint16_t PcapReader::ddosdEtherType(const PcapPacket& pcap_packet) const {
    if (l2EtherType(pcap_packet) != ETHERTYPE_DDOSD)
        throw std::runtime_error("could not extract DDoSD information from packet");
    const struct ddosd_t* ddosd_header = reinterpret_cast<const struct ddosd_t*>(pcap_packet.data + l2HeaderLength());
    return ntohs(ddosd_header->ether_type);
}

}
