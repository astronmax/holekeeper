#pragma once

#include <QtCore/QByteArray>

#include <type_traits>

template <typename T>
QByteArray int_to_bytes(const T integer)
{
    if (!std::is_integral_v<T>) {
        throw std::invalid_argument { "Needs integral type" };
    }

    QByteArray result {};
    for (size_t i = 0; i < sizeof(T); i++) {
        result.push_back((integer >> (8 * (sizeof(T) - i - 1))) & 0xFF);
    }

    return result;
}

template <typename T>
auto bytes_to_int(const QByteArray bytes) -> T
{
    if (!std::is_integral_v<T>) {
        throw std::invalid_argument { "Needs integral type" };
    }

    T result {};
    for (auto byte : bytes) {
        result = (result << 8) | static_cast<uint8_t>(byte);
    }

    return result;
}
