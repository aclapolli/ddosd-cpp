#pragma once

#include <cstdint>

#include "ExtendedCountSketch.hpp"
#include "LpmLookupTable.hpp"

namespace DDoSD {

class EntropyEstimator {
    public:
        EntropyEstimator(uint32_t window_size, uint32_t sketch_depth, uint32_t sketch_width);
        EntropyEstimator(uint32_t window_size,
                         uint32_t sketch_depth,
                         uint32_t sketch_width,
                         const ExtendedCountSketch::HashCoefficients& sketch_h_coefficients,
                         const ExtendedCountSketch::HashCoefficients& sketch_g_coefficients);

        EntropyEstimator(const EntropyEstimator&) = delete;
        EntropyEstimator& operator=(const EntropyEstimator&) = delete;

        void update(uint32_t src_ipv4, uint32_t dst_ipv4);
        void reset();

        uint32_t srcEntropy() const;
        uint32_t dstEntropy() const;

    private:
        uint8_t mLog2M;
        ExtendedCountSketch mSrcSketch;
        ExtendedCountSketch mDstSketch;
        LpmLookupTable<uint32_t> mLookupTable;
        uint32_t mSrcS;
        uint32_t mDstS;

        static uint32_t f(uint32_t x);
};

}
