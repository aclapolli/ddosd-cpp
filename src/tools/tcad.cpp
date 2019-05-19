#include <string>
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>
#include <boost/algorithm/string.hpp>
#include <cstdint>

#include "TrafficCharacterizer.hpp"

int main(int argc, char* argv[]) {
    uint32_t training_length;
    double smoothing_coefficient;
    double sensitivity_coefficient;

    boost::program_options::options_description options("general options");
    options.add_options()
            ("help,h", "show this help message and exit")
            ("training-length,t", boost::program_options::value(&training_length), "training length (number of windows)")
            ("smoothing-coefficient,s", boost::program_options::value(&smoothing_coefficient), "smoothing coefficient")
            ("sensitivity-coefficient,k", boost::program_options::value(&sensitivity_coefficient), "sensitivity coefficient");

    boost::program_options::variables_map variables_map;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv)
                                  .options(options)
                                  .run(), variables_map);

    if (variables_map.count("help") || !variables_map.count("training-length") || !variables_map.count("smoothing-coefficient") || !variables_map.count("sensitivity-coefficient")) {
        std::cerr << "usage: tcad [-h] -t <training_length> -s <smoothing_coefficient> -k <sensitivity_coefficient>" << std::endl;
        std::cerr << options << std::endl;
        return -1;
    }

    boost::program_options::notify(variables_map);

    try {
        const uint8_t alpha = static_cast<uint8_t>(round(pow(2, 8)*smoothing_coefficient));
        const uint8_t k = static_cast<uint8_t>(round(pow(2, 3)*sensitivity_coefficient));

        std::vector<std::unique_ptr<DDoSD::TrafficCharacterizer>> characterizers;

        std::string line;

        uint32_t ow_counter = 0;
        while (std::getline(std::cin, line)) {
            ++ow_counter;

            std::vector<std::string> columns;
            boost::split(columns, line, boost::is_any_of(" "));

            std::cout << columns.at(0) << " ";

            for (std::size_t i = 1; i < columns.size() - 1; i += 2) {
                if (characterizers.size() < (i + 1)/2)
                    characterizers.emplace_back(new DDoSD::TrafficCharacterizer(alpha));

                const uint32_t src_entropy = static_cast<uint32_t>(std::stoul(columns.at(i)));
                const uint32_t dst_entropy = static_cast<uint32_t>(std::stoul(columns.at(i + 1)));

                const auto& characterizer = characterizers.at(i/2);
                const uint32_t src_thresh = characterizer->srcEwma() + ((k*characterizer->srcEwmmd()) >> 3);
                const uint32_t dst_thresh = characterizer->dstEwma() - ((k*characterizer->dstEwmmd()) >> 3);

                const bool alarm = ow_counter > training_length && ((src_entropy << 14) > src_thresh || (dst_entropy << 14) < dst_thresh);
                if (!alarm)
                    characterizer->update(src_entropy, dst_entropy);

                std::cout << src_entropy << " " << characterizer->srcEwma() << " " << characterizer->srcEwmmd() << " ";
                std::cout << dst_entropy << " " << characterizer->dstEwma() << " " << characterizer->dstEwmmd() << " ";
                std::cout << alarm;
            }

            std::cout << std::endl;
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}
