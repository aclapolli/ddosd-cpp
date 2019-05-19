#pragma once

#include <cstdint>
#include <unordered_map>

namespace DDoSD {

class EntropyCalculator {
    public:
        EntropyCalculator();

        EntropyCalculator(const EntropyCalculator&) = delete;
        EntropyCalculator& operator=(const EntropyCalculator&) = delete;

        void update(uint32_t src_ipv4, uint32_t dst_ipv4);
        void reset();
        double srcEntropy() const;
        double dstEntropy() const;

    private:
        uint32_t mPktCounter;
        std::unordered_map<uint32_t, uint32_t> mSrcHistogram;
        std::unordered_map<uint32_t, uint32_t> mDstHistogram;
};

}
