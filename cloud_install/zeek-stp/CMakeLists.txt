cmake_minimum_required(VERSION 3.15)
project(zeek-stp LANGUAGES CXX)

include(ZeekPlugin)

zeek_plugin_begin(EventMill STP)
zeek_plugin_cc(src/Plugin.cc src/STP.cc)
zeek_plugin_bif(src/events.bif)
zeek_plugin_end()
