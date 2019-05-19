#include "TrafficCharacterizer.hpp"

namespace DDoSD {

TrafficCharacterizer::TrafficCharacterizer(uint8_t alpha)
    : mAlpha(alpha), mSetup(false) { }

void TrafficCharacterizer::update(uint32_t src_entropy, uint32_t dst_entropy) {
    if (!mSetup) {
        mSrcEwma = src_entropy << 14;
        mSrcEwmmd = 0;
        mDstEwma = dst_entropy << 14;
        mDstEwmmd = 0;
        mSetup = true;
    } else {
        mSrcEwma = ((mAlpha*src_entropy) << 6) + (((256 - mAlpha)*mSrcEwma) >> 8);
        uint32_t abs_diff = mSrcEwma > (src_entropy << 14)? mSrcEwma - (src_entropy << 14) :
                                                             (src_entropy << 14) - mSrcEwma;
        mSrcEwmmd = ((mAlpha*abs_diff) >> 8) + (((256 - mAlpha)*mSrcEwmmd) >> 8);

        mDstEwma = ((mAlpha*dst_entropy) << 6) + (((256 - mAlpha)*mDstEwma) >> 8);
        abs_diff = mDstEwma > (dst_entropy << 14)? mDstEwma - (dst_entropy << 14) :
                                                    (dst_entropy << 14) - mDstEwma;
        mDstEwmmd = ((mAlpha*abs_diff) >> 8) + (((256 - mAlpha)*mDstEwmmd) >> 8);
    }
}

uint32_t TrafficCharacterizer::srcEwma() const {
    return mSrcEwma;
}

uint32_t TrafficCharacterizer::srcEwmmd() const {
    return mSrcEwmmd;
}

uint32_t TrafficCharacterizer::dstEwma() const {
    return mDstEwma;
}

uint32_t TrafficCharacterizer::dstEwmmd() const {
    return mDstEwmmd;
}

}
