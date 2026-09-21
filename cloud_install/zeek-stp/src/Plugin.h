#pragma once

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin::EventMill_STP {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}  // namespace zeek::plugin::EventMill_STP
