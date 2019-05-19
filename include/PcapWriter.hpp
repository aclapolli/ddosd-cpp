#pragma once

#include <pcap.h>
#include <cstdint>
#include <string>

#include "PcapReader.hpp"

namespace DDoSD {

class PcapWriter {
    public:
        PcapWriter(const std::string& pcap_filename, int mLinkType = DLT_EN10MB, int snaplen = 1500);

        PcapWriter(const PcapWriter&) = delete;
        PcapWriter& operator=(const PcapWriter&) = delete;

        ~PcapWriter();

        void writePacket(const PcapPacket& packet);
        void writePacket(uint32_t src_ipv4, uint32_t dst_ipv4, struct timeval ts, void* payload, uint16_t payload_len);
        void writePacket(uint32_t src_ipv4, uint32_t dst_ipv4, void* payload, uint16_t payload_len);

    private:
        pcap_t* mPcapHandler;
        pcap_dumper_t* mPcapDumper;
        int mLinkType;
        struct timeval mLastTs;

        static char* ipv4ToChar(char* dst, uint32_t ipv4);
};

}
