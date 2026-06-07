#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <vector>

namespace Scanner {

struct APInfo {
    String ssid;
    String bssid;
    int8_t rssi;
    uint8_t channel;
    uint8_t encryption;
};

void setup();
std::vector<APInfo> scanNetworks();
String scanToJson();

} // namespace Scanner
