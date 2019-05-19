#include <string>
#include <boost/program_options.hpp>
#include <iostream>

#include "PcapReader.hpp"

int main(int argc, char* argv[]) {
    std::string pcap_filename;

    boost::program_options::options_description options("general options");
    options.add_options()
            ("help,h", "show this help message and exit");

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

    if (variables_map.count("help") || !variables_map.count("pcap_filename")) {
        std::cerr << "usage: ercnv [-h] <pcap_filename>" << std::endl;
        std::cerr << options << std::endl;
        return -1;
    }

    boost::program_options::notify(variables_map);

    try {
        DDoSD::PcapReader pcap_reader(pcap_filename);
        DDoSD::PcapPacket pcap_packet;
        while (pcap_reader.nextPacket(pcap_packet) > 0) {
            std::cout << 1000000*pcap_packet.metadata->ts.tv_sec + pcap_packet.metadata->ts.tv_usec << " ";
            std::cout << pcap_reader.ddosdSrcEntropy(pcap_packet) << " ";
            std::cout << pcap_reader.ddosdSrcEwma(pcap_packet) << " ";
            std::cout << pcap_reader.ddosdSrcEwmmd(pcap_packet) << " ";
            std::cout << pcap_reader.ddosdDstEntropy(pcap_packet) << " ";
            std::cout << pcap_reader.ddosdDstEwma(pcap_packet) << " ";
            std::cout << pcap_reader.ddosdDstEwmmd(pcap_packet) << " ";
            std::cout << static_cast<uint16_t>(pcap_reader.ddosdAlarm(pcap_packet)) << std::endl;
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}
