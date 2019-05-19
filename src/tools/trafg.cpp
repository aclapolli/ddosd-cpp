#include <sys/time.h>
#include <cstdint>
#include <string>
#include <boost/program_options.hpp>
#include <iostream>
#include <random>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>

#include "PcapReader.hpp"
#include "PcapWriter.hpp"

#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))

void generatePayload(char* payload, struct timeval ts, bool is_attack);

int main(int argc, char* argv[]) {
    uint32_t packet_count;
    double attack_proportion;
    std::string legitimate_pcap_filename;
    std::string malicious_pcap_filename;
    std::string output_pcap_filename;

    boost::program_options::options_description options("general options");
    options.add_options()
            ("help,h", "show this help message and exit")
            ("packet-count,n", boost::program_options::value(&packet_count), "packet count")
            ("attack-proportion,a", boost::program_options::value(&attack_proportion), "attack proportion");

    boost::program_options::options_description hidden_options;
    hidden_options.add_options()
            ("legitimate_pcap_filename", boost::program_options::value(&legitimate_pcap_filename), "legimitate pcap filename")
            ("malicious_pcap_filename", boost::program_options::value(&malicious_pcap_filename), "malicious pcap filename")
            ("output_pcap_filename", boost::program_options::value(&output_pcap_filename), "output pcap filename");

    boost::program_options::options_description all_options;
    all_options.add(options);
    all_options.add(hidden_options);

    boost::program_options::positional_options_description positional_options;
    positional_options.add("legitimate_pcap_filename", 1);
    positional_options.add("malicious_pcap_filename", 1);
    positional_options.add("output_pcap_filename", 1);

    boost::program_options::variables_map variables_map;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv)
                                  .options(all_options)
                                  .positional(positional_options)
                                  .run(), variables_map);

    if (variables_map.count("help") || !variables_map.count("packet-count") || !variables_map.count("attack-proportion") ||
         !variables_map.count("legitimate_pcap_filename") || !variables_map.count("malicious_pcap_filename") || !variables_map.count("output_pcap_filename")) {
        std::cerr << "usage: trafg [-h] -n <packet_count> -a <attack_proportion> <legitimate_pcap_filename> <malicious_pcap_filename> <output_pcap_filename>" << std::endl;
        std::cerr << options << std::endl;
        return -1;
    }

    boost::program_options::notify(variables_map);

    try {
        DDoSD::PcapReader legitimate_pcap_reader(legitimate_pcap_filename);
        DDoSD::PcapReader malicious_pcap_reader(malicious_pcap_filename);
        DDoSD::PcapPacket pcap_packet;
        struct timeval ts, last_ts;

        DDoSD::PcapWriter pcap_writer(output_pcap_filename);

        for (uint32_t i = 0; i < packet_count/2; i++) {
            legitimate_pcap_reader.nextPacket(pcap_packet);
            ts = pcap_packet.metadata->ts;
            char payload[17];
            generatePayload(payload, ts, false);
            pcap_writer.writePacket(legitimate_pcap_reader.srcIpv4(pcap_packet),
                                    legitimate_pcap_reader.dstIpv4(pcap_packet),
                                    pcap_packet.metadata->ts,
                                    payload, 17);
        }

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dist(0, 1);

        bool attack_started = false;

        for (uint32_t i = 0; i < packet_count; i++) {
            if (i+1 > 0.25*packet_count && i+1 <= 0.75*packet_count && dist(gen) < attack_proportion) {
                malicious_pcap_reader.nextPacket(pcap_packet);
                char payload[17];
                generatePayload(payload, ts, true);
                pcap_writer.writePacket(malicious_pcap_reader.srcIpv4(pcap_packet),
                                        malicious_pcap_reader.dstIpv4(pcap_packet),
                                        payload, 17);
                last_ts = ts;
                if (!attack_started) {
                    std::cout << 1000000*ts.tv_sec + ts.tv_usec << std::endl;
                    attack_started = true;
                }
            }
            else {
                legitimate_pcap_reader.nextPacket(pcap_packet);
                ts = pcap_packet.metadata->ts;
                char payload[17];
                generatePayload(payload, ts, false);
                pcap_writer.writePacket(legitimate_pcap_reader.srcIpv4(pcap_packet),
                                        legitimate_pcap_reader.dstIpv4(pcap_packet),
                                        pcap_packet.metadata->ts,
                                        payload, 17);
            }
        }
        std::cout << 1000000*last_ts.tv_sec + last_ts.tv_usec << std::endl;
    }
    catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}

void generatePayload(char* payload, struct timeval ts, bool is_attack) {
    uint64_t aux = htonll(ts.tv_sec);
    memcpy(payload, &aux, 8);
    aux = htonll(ts.tv_usec);
    memcpy(payload + 8, &aux, 8);

    if (!is_attack)
        payload[16] = '\x00';
    else
        payload[16] = '\x01';
}
