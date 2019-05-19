#include "EntropyEstimator.hpp"

#include <cmath>

namespace DDoSD {

EntropyEstimator::EntropyEstimator(uint32_t window_size, uint32_t sketch_depth, uint32_t sketch_width)
    : mLog2M(static_cast<uint8_t>(round(log2(window_size)))),
      mSrcSketch(sketch_depth, sketch_width),
      mDstSketch(sketch_depth, sketch_width),
      mLookupTable(&EntropyEstimator::f, window_size, 1),
      mSrcS(0),
      mDstS(0) { }

EntropyEstimator::EntropyEstimator(uint32_t window_size,
                                   uint32_t sketch_depth,
                                   uint32_t sketch_width,
                                   const ExtendedCountSketch::HashCoefficients& sketch_h_coefficients,
                                   const ExtendedCountSketch::HashCoefficients& sketch_g_coefficients)
    : mLog2M(static_cast<uint8_t>(round(log2(window_size)))),
      mSrcSketch(sketch_depth, sketch_width, sketch_h_coefficients, sketch_g_coefficients),
      mDstSketch(sketch_depth, sketch_width, sketch_h_coefficients, sketch_g_coefficients),
      mLookupTable(&EntropyEstimator::f, window_size, 1),
      mSrcS(0),
      mDstS(0) { }

uint32_t EntropyEstimator::f(uint32_t x) {
    if (x < 2)
        return 0;
    return static_cast<uint32_t>(
                round(pow(2, 4)*(
                          x*log2(static_cast<double>(x)) -
                          (x - 1)*log2(static_cast<double>(x - 1))
                      )));
}

void EntropyEstimator::update(uint32_t src_ipv4, uint32_t dst_ipv4) {
    const int32_t src_fx = mSrcSketch.update(src_ipv4);
    if (src_fx > 0)
        mSrcS += mLookupTable.get(static_cast<uint32_t>(src_fx));

    const int32_t dst_fx = mDstSketch.update(dst_ipv4);
    if (dst_fx > 0)
        mDstS += mLookupTable.get(static_cast<uint32_t>(dst_fx));
}

void EntropyEstimator::reset() {
    mSrcSketch.reset();
    mSrcS = 0;
    mDstSketch.reset();
    mDstS = 0;
}

uint32_t EntropyEstimator::srcEntropy() const {
    return (mLog2M << 4) - (mSrcS >> mLog2M);
}

uint32_t EntropyEstimator::dstEntropy() const {
    return (mLog2M << 4) - (mDstS >> mLog2M);
}

}
