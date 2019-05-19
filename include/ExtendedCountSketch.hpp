#pragma once

#include <cstdint>
#include <random>
#include <array>
#include <vector>

namespace DDoSD {


class ExtendedCountSketch {
    public:
        using HashCoefficients = std::array<std::vector<uint32_t>, 2>;

        ExtendedCountSketch(uint32_t depth, uint32_t width);
        ExtendedCountSketch(uint32_t depth,
                            uint32_t width,
                            const HashCoefficients& h_coefficients,
                            const HashCoefficients& g_coefficients);

        ExtendedCountSketch(const ExtendedCountSketch&) = delete;
        ExtendedCountSketch& operator=(const ExtendedCountSketch&) = delete;

        int32_t update(uint32_t key);
        void reset();

    private:
        const static uint32_t LARGE_PRIME = 179424691;

        uint32_t mDepth;
        uint32_t mWidth;
        uint8_t mCurrentState;
        HashCoefficients mHCoefficients;
        HashCoefficients mGCoefficients;
        std::random_device mRandomDevice;
        std::mt19937 mRandomGenerator;
        std::uniform_int_distribution<uint32_t> mRandomDistribution;
        std::vector<std::vector<int32_t>> mCounters;
        std::vector<std::vector<uint8_t>> mStates;

        static uint32_t gcd(uint32_t a, uint32_t b);
        uint32_t relativePrime(uint32_t n);
        uint32_t hash(uint32_t index, uint32_t key);
        int16_t ghash(uint32_t index, uint32_t key);
};

}
