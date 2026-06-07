#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>

// 直接引入模块头文件，保证接口一致性
#include "scanner.h"
#include "capture.h"

namespace WebUI {

extern WebServer server;
extern DNSServer dnsServer;

void setup();
void loop();

// 内嵌 HTML 页面
extern const char MAIN_PAGE[] PROGMEM;

} // namespace WebUI
