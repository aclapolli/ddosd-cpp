#include <cstdint>
#include <string>
#include <boost/program_options.hpp>
#include <iostream>
#include <random>
#include <stdexcept>

#include "EntropyCalculator.hpp"
#include "PcapReader.hpp"

int main(int argc, char* argv[]) {
    uint32_t window_size;
    double sampling_prob;
    std::string pcap_filename;

    boost::program_options::options_description options("general options");
    options.add_options()
            ("help,h", "show this help message and exit")
            ("window-size,w", boost::program_options::value(&window_size), "observation window size")
            ("sampling-prob,s", boost::program_options::value(&sampling_prob), "sampling probability");

    boost::program_options::options_description hidden_options;
    hidden_options.add_options()
            ("pcap_filename", boost::program_options::value(&pcap_filename)->required(), "pcap filename");

    boost::program_options::options_description all_options;
    all_options.add(options);
    all_options.add(hidden_options);

    boost::program_options::positional_options_description positional_options;
    positional_options.add("pcap_filename", 1);

    boost::program_options::variables_map variables_map;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv)
                                  .options(all_options)
                                  .positional(positional_options)
                                  .run(), variables_map);

    if (variables_map.count("help") || !variables_map.count("window-size") || !variables_map.count("sampling-prob") || !variables_map.count("pcap_filename")) {
        std::cerr << "usage: psamp [-h] -w <window_size> -s <sampling_prob> <pcap_filename>" << std::endl;
        std::cerr << options << std::endl;
        return -1;
    }

    boost::program_options::notify(variables_map);

    try {
        DDoSD::EntropyCalculator entropy_calculator;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dist(0, 1);

        DDoSD::PcapReader pcap_reader(pcap_filename);
        DDoSD::PcapPacket pcap_packet;

        std::cout.precision(8);

        uint32_t packet_count = 0;
        while (pcap_reader.nextPacket(pcap_packet) > 0) {
            if (packet_count == window_size) {
                std::cout << 1000000*pcap_packet.metadata->ts.tv_sec + pcap_packet.metadata->ts.tv_usec << " "
                          << entropy_calculator.srcEntropy() << " "
                          << entropy_calculator.dstEntropy() << std::endl;
                entropy_calculator.reset();
                packet_count = 0;
            }

            if (dist(gen) <= sampling_prob) {
                entropy_calculator.update(pcap_reader.srcIpv4(pcap_packet), pcap_reader.dstIpv4(pcap_packet));
                packet_count++;
            }
        }
    }
    catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}
