#include "Plugin.h"
#include "STP.h"

namespace zeek::plugin::EventMill_STP {

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::packet_analysis::Component(
        "STP",
        zeek::packet_analysis::EventMill::STP::STPAnalyzer::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "EventMill::STP";
    config.description = "STP/RSTP/MSTP BPDU packet analyzer for Spanning Tree Protocol";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}

Plugin plugin;

}  // namespace zeek::plugin::EventMill_STP
