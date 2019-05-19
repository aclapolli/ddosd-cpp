#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <unordered_map>
#include <iostream>

namespace DDoSD {

struct LpmLookupKey {
    uint32_t base;
    uint8_t prefix_len;

    bool operator==(const LpmLookupKey& b) const {
        return base == b.base && prefix_len == b.prefix_len;
    }

    bool operator<(const LpmLookupKey& b) const {
        return base != b.base? base < b.base : prefix_len < b.prefix_len;
    }
};

template <typename T>
class LpmLookupTable {
    public:
        LpmLookupTable(std::function<T(uint32_t)> f, uint32_t max, T max_error) {
            uint32_t x = 0;
            while (x <= max) {
                LpmLookupKey key;
                for (key.prefix_len = 1; key.prefix_len < 32; ++key.prefix_len) {
                    key.base = x & ~(0xffffffff >> key.prefix_len);
                    if (key.base >= x) {
                        const uint32_t last = key.base + (1 << (32 - key.prefix_len)) - 1;

                        const T f_base = f(key.base);
                        const T f_last = f(last);
                        const T diff = f_last > f_base? f_last - f_base : f_base - f_last;
                        if (diff <= max_error) {
                            mLookupTable.insert(std::make_pair(key, (f_base + f_last) >> 1));
                            x = last + 1;
                            break;
                        }
                    }

                    if (key.prefix_len == 31) {
                        key.base = x;
                        key.prefix_len = 32;
                        mLookupTable.insert(std::make_pair(key, f(x)));
                        ++x;
                    }
                }
            }
        }

        LpmLookupTable(const LpmLookupTable&) = delete;
        LpmLookupTable& operator=(const LpmLookupTable&) = delete;

        T get(uint32_t x) const {
            for (int8_t prefix_len = 32; prefix_len >= 0; --prefix_len) {
                LpmLookupKey key;
                key.base = prefix_len == 32? x : x & ~(0xffffffff >> prefix_len);
                key.prefix_len = static_cast<uint8_t>(prefix_len);
                if (mLookupTable.find(key) != mLookupTable.end()) {
                    return mLookupTable.at(key);
                }
            }

            throw std::runtime_error("could not find LPM Lookup table entry for " + std::to_string(x) + "!");
        }

        void dump(std::ostream& stream = std::cout) const {
            const std::map<LpmLookupKey, T> ordered_lt(mLookupTable.begin(), mLookupTable.end());
            for (const auto& it : ordered_lt)
                stream << it.first.base << "/" << static_cast<uint32_t>(it.first.prefix_len) << " " << it.second << std::endl;
        }

        uint32_t size() const {
            return mLookupTable.size();
        }

    private:
        std::unordered_map<LpmLookupKey, T> mLookupTable;
};

}

namespace std {
    template<>
    struct hash<DDoSD::LpmLookupKey> {
        std::size_t operator()(const DDoSD::LpmLookupKey& k) const {
            return std::hash<uint32_t>()(k.base) ^ std::hash<uint8_t>()(k.prefix_len);
        }
    };
}
