#pragma once

#include <cstdint>

namespace DDoSD {

class TrafficCharacterizer {
    public:
        TrafficCharacterizer(uint8_t alpha);

        TrafficCharacterizer(const TrafficCharacterizer&) = delete;
        TrafficCharacterizer& operator=(const TrafficCharacterizer&) = delete;

        void update(uint32_t src_entropy, uint32_t dst_entropy);

        uint32_t srcEwma() const;
        uint32_t srcEwmmd() const;
        uint32_t dstEwma() const;
        uint32_t dstEwmmd() const;

    private:
        uint8_t mAlpha;
        bool mSetup;
        uint32_t mSrcEwma;
        uint32_t mSrcEwmmd;
        uint32_t mDstEwma;
        uint32_t mDstEwmmd;
};

}
