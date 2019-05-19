#include <cstdint>
#include <boost/program_options.hpp>
#include <functional>
#include <iostream>
#include <cmath>

#include "LpmLookupTable.hpp"

uint32_t f(uint32_t x, uint16_t precision);

int main(int argc, char* argv[]) {
    uint16_t bit_precision;
    uint32_t max_x;
    uint32_t max_error;

    boost::program_options::options_description options("general options");
    options.add_options()
            ("help,h", "show this help message and exit")
            ("bit-precision,b", boost::program_options::value(&bit_precision), "fixed-point representation bit precision")
            ("max-x,m", boost::program_options::value(&max_x), "LPM lookup table maximum domain value")
            ("max-error,e", boost::program_options::value(&max_error),"LPM lookup table maximum approximation error 2^max_error");

    boost::program_options::variables_map variables_map;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv)
                                  .options(options)
                                  .run(), variables_map);

    if (variables_map.count("help") || !variables_map.count("bit-precision") || !variables_map.count("max-x") || !variables_map.count("max-error")) {
        std::cerr << "usage: lpm [-h] -b <bit_precision> -m <max_x> -e <max_error>" << std::endl;
        std::cerr << options << std::endl;
        return -1;
    }

    boost::program_options::notify(variables_map);

    try {
        const std::function<uint16_t(uint32_t)> f_ptr = std::bind(f, std::placeholders::_1, bit_precision);
        const DDoSD::LpmLookupTable<uint32_t> lookup_table(f_ptr, max_x, max_error);

        std::cout << "total " << lookup_table.size() << " entries" << std::endl;
        lookup_table.dump();
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}

uint32_t f(uint32_t x, uint16_t precision) {
    if (x < 2)
        return 0;
    return static_cast<uint32_t>(round(pow(2, precision)*(x*log2(static_cast<double>(x)) - (x-1)*log2(static_cast<double>(x-1)))));
}
