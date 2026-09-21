#pragma once

#include <zeek/packet_analysis/Analyzer.h>
#include <zeek/packet_analysis/Component.h>

namespace zeek::packet_analysis::EventMill::STP {

class STPAnalyzer : public zeek::packet_analysis::Analyzer {
public:
    STPAnalyzer();
    ~STPAnalyzer() override = default;

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() {
        return std::make_shared<STPAnalyzer>();
    }
};

}  // namespace zeek::packet_analysis::EventMill::STP
