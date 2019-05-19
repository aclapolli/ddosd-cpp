#include <string>
#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>
#include <boost/optional.hpp>
#include <vector>
#include <memory>

#include "nlohmann/json.hpp"
#include "EntropyCalculator.hpp"
#include "EntropyEstimator.hpp"
#include "PcapReader.hpp"

void parseHashCoefficients(const nlohmann::json coefficients,
                           DDoSD::ExtendedCountSketch::HashCoefficients& h_coefficients,
                           DDoSD::ExtendedCountSketch::HashCoefficients& g_coefficients);

int main(int argc, char* argv[]) {
    std::string config_filename;
    std::string pcap_filename;

    boost::program_options::options_description options("general options");
    options.add_options()
            ("help,h", "show this help message and exit")
            ("config,c", boost::program_options::value(&config_filename), "configuration filename");

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

    if (variables_map.count("help") || !variables_map.count("config") || !variables_map.count("pcap_filename")) {
        std::cerr << "usage: ee [-h] -c <config_filename> <pcap_filename>" << std::endl;
        std::cerr << options << std::endl;
        return -1;
    }

    boost::program_options::notify(variables_map);

    try {
        std::ifstream config_file(config_filename);
        nlohmann::json config;
        config_file >> config;

        boost::optional<DDoSD::EntropyCalculator> baseline;
        if (config.at("baseline").get<bool>())
            baseline.emplace();

        std::vector<std::unique_ptr<DDoSD::EntropyEstimator>> estimators;
        if (config.find("estimators") != config.end()) {
            const auto& estimators_config = config.at("estimators");

            for (std::size_t depth_index = 0; depth_index < estimators_config.at("depth_levels").size(); ++depth_index) {
                const uint32_t sketch_depth = estimators_config.at("depth_levels").at(depth_index).get<uint32_t>();

                if (estimators_config.find("coefficients") != estimators_config.end()) {
                    DDoSD::ExtendedCountSketch::HashCoefficients h_coefficients;
                    DDoSD::ExtendedCountSketch::HashCoefficients g_coefficients;
                    parseHashCoefficients(estimators_config.at("coefficients").at(depth_index),
                                          h_coefficients,
                                          g_coefficients);

                    for (const auto& sketch_width : estimators_config.at("width_levels"))
                        for (uint32_t rep = 0; rep < estimators_config.at("repetitions").get<uint32_t>(); ++rep)
                            estimators.emplace_back(new DDoSD::EntropyEstimator(config.at("window_size").get<uint32_t>(),
                                                                                sketch_depth,
                                                                                sketch_width,
                                                                                h_coefficients,
                                                                                g_coefficients));
                } else {
                    for (const auto& sketch_width : estimators_config.at("width_levels"))
                        for (uint32_t rep = 0; rep < estimators_config.at("repetitions").get<uint32_t>(); ++rep)
                            estimators.emplace_back(new DDoSD::EntropyEstimator(config.at("window_size").get<uint32_t>(),
                                                                                sketch_depth,
                                                                                sketch_width));
                }
            }
        }

        DDoSD::PcapReader pcap_reader(pcap_filename);
        DDoSD::PcapPacket pcap_packet;

        std::cout.precision(8);

        uint32_t packet_count = 0;
        while (pcap_reader.nextPacket(pcap_packet) > 0) {
            if (packet_count == config.at("window_size").get<uint32_t>()) {
                std::cout << 1000000*pcap_packet.metadata->ts.tv_sec + pcap_packet.metadata->ts.tv_usec << " ";
                if (baseline) {
                    std::cout << pow(2, 4)*baseline.get().srcEntropy() << " "
                              << pow(2, 4)*baseline.get().dstEntropy() << " ";
                    baseline.get().reset();
                }
                for (auto& it : estimators) {
                    std::cout << it->srcEntropy() << " "
                              << it->dstEntropy() << " ";
                    it->reset();
                }
                std::cout << std::endl;
                packet_count = 0;
            }

            uint32_t src_ipv4, dst_ipv4;
            try {
                src_ipv4 = pcap_reader.srcIpv4(pcap_packet);
                dst_ipv4 = pcap_reader.dstIpv4(pcap_packet);
            }
            catch (std::exception&) {
                continue;
            }

            if (baseline)
                baseline.get().update(src_ipv4, dst_ipv4);
            for (auto& it : estimators)
                it->update(src_ipv4, dst_ipv4);

            packet_count++;
        }

        if (packet_count > 0) {
            std::cout << 1000000*pcap_packet.metadata->ts.tv_sec + pcap_packet.metadata->ts.tv_usec << " ";
            if (baseline) {
                std::cout << pow(2, 4)*baseline.get().srcEntropy() << " "
                          << pow(2, 4)*baseline.get().dstEntropy() << " ";
            }
            for (auto& it : estimators) {
                std::cout << it->srcEntropy() << " "
                          << it->dstEntropy() << " ";
            }
            std::cout << std::endl;
        }
    }
    catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}

void parseHashCoefficients(const nlohmann::json coefficients,
                           DDoSD::ExtendedCountSketch::HashCoefficients& h_coefficients,
                           DDoSD::ExtendedCountSketch::HashCoefficients& g_coefficients) {
    for (const auto& a : coefficients.at("h").at("a"))
        h_coefficients.at(0).push_back(a.get<uint32_t>());
    for (const auto& b : coefficients.at("h").at("b"))
        h_coefficients.at(1).push_back(b.get<uint32_t>());

    for (const auto& a : coefficients.at("g").at("a"))
        g_coefficients.at(0).push_back(a.get<uint32_t>());
    for (const auto& b : coefficients.at("g").at("b"))
        g_coefficients.at(1).push_back(b.get<uint32_t>());
}
