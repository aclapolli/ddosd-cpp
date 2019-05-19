#include <algorithm>
#include <iostream>

#include "ExtendedCountSketch.hpp"

namespace DDoSD {

ExtendedCountSketch::ExtendedCountSketch(uint32_t depth, uint32_t width)
    : mDepth(depth),
      mWidth(width),
      mCurrentState(0),
      mRandomGenerator(mRandomDevice()),
      mRandomDistribution(1, LARGE_PRIME),
      mCounters(depth, std::vector<int32_t>(width, 0)),
      mStates(depth, std::vector<uint8_t>(width, 0)) {

    mHCoefficients.fill(std::vector<uint32_t>(depth, 0));
    mGCoefficients.fill(std::vector<uint32_t>(depth, 0));

    for (uint32_t i = 0; i < mDepth; ++i) {
        mHCoefficients[0][i] = mRandomDistribution(mRandomGenerator);
        mHCoefficients[1][i] = relativePrime(mHCoefficients[0][i]);

        mGCoefficients[0][i] = mRandomDistribution(mRandomGenerator);
        mGCoefficients[1][i] = relativePrime(mHCoefficients[0][i]);
    }
}

ExtendedCountSketch::ExtendedCountSketch(uint32_t depth,
                                         uint32_t width,
                                         const HashCoefficients& h_coefficients,
                                         const HashCoefficients& g_coefficients)
    : mDepth(depth),
      mWidth(width),
      mCurrentState(0),
      mHCoefficients(h_coefficients),
      mGCoefficients(g_coefficients),
      mCounters(depth, std::vector<int32_t>(width, 0)),
      mStates(depth, std::vector<uint8_t>(width, 0)) { }


uint32_t ExtendedCountSketch::gcd(uint32_t a, uint32_t b) {
    uint32_t tmp;
    while (b != 0) {
        tmp = a % b;
        a = b;
        b = tmp;
    }
    return a;
}

uint32_t ExtendedCountSketch::relativePrime(uint32_t n) {
    uint32_t r = mRandomDistribution(mRandomGenerator);
    uint32_t t = gcd(r, n);
    while (t > 1) {
        r /= t;
        t = gcd(r, n);
    }
    return r;
}

uint32_t ExtendedCountSketch::hash(uint32_t index, uint32_t key) {
    return ((static_cast<uint64_t>(mHCoefficients[0][index])*key + mHCoefficients[1][index]) % LARGE_PRIME) % mWidth;
}

int16_t ExtendedCountSketch::ghash(uint32_t index, uint32_t key) {
    return static_cast<int16_t>(2)*(((static_cast<uint64_t>(mGCoefficients[0][index])*key + mGCoefficients[1][index]) % LARGE_PRIME) % 2) - 1;
}

int32_t ExtendedCountSketch::update(uint32_t key) {
    std::vector<int32_t> counts;
    for (uint32_t i = 0; i < mDepth; ++i) {
        const uint32_t h = hash(i, key);
        const int32_t g = ghash(i, key);

        if (mStates[i][h] != mCurrentState) {
            mCounters[i][h] = g;
            mStates[i][h] = mCurrentState;
        } else {
            mCounters[i][h] += g;
        }

        counts.push_back(g*mCounters[i][h]);
    }

    // Median
    sort(counts.begin(), counts.end());
    const size_t size = counts.size();
    if (size % 2 == 0)
        return (counts[size/2 - 1] + counts[size/2])/2;
    else
        return counts[size/2];
}

void ExtendedCountSketch::reset() {
    ++mCurrentState;
}

}
