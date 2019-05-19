#include "EntropyCalculator.hpp"

#include <cmath>

namespace DDoSD {

EntropyCalculator::EntropyCalculator()
    : mPktCounter(0) { }

void EntropyCalculator::update(uint32_t src_ipv4, uint32_t dst_ipv4) {
    ++mPktCounter;

    if (mSrcHistogram.find(src_ipv4) == mSrcHistogram.end())
        mSrcHistogram[src_ipv4] = 1;
    else
        ++mSrcHistogram[src_ipv4];

    if (mDstHistogram.find(dst_ipv4) == mDstHistogram.end())
        mDstHistogram[dst_ipv4] = 1;
    else
        ++mDstHistogram[dst_ipv4];
}

void EntropyCalculator::reset() {
    mPktCounter = 0;
    mSrcHistogram.clear();
    mDstHistogram.clear();
}

double EntropyCalculator::srcEntropy() const {
    double src_entropy_norm = 0;
    for (auto it : mSrcHistogram)
        src_entropy_norm += it.second*log2(it.second);
    return log2(mPktCounter) - src_entropy_norm/mPktCounter;
}

double EntropyCalculator::dstEntropy() const {
    double dst_entropy_norm = 0;
    for (auto it : mDstHistogram)
        dst_entropy_norm += it.second*log2(it.second);
    return log2(mPktCounter) - dst_entropy_norm/mPktCounter;
}

}
