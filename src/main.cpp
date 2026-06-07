#include <Arduino.h>
#include <WiFi.h>
#include "scanner.h"
#include "capture.h"
#include "web.h"

namespace {

constexpr const char* kProjectName = "ESP32-S3 WiFi Handshake Sniffer";
constexpr const char* kApSsid = "esp32-s3-wifi-handshake-sniffer";
String gSerialLine;

void startManagementAp() {
    WiFi.mode(WIFI_MODE_APSTA);
    WiFi.softAP(kApSsid, nullptr, 1, 0, 4);
}

void printSerialHelp() {
    Serial.println("[Serial] Commands:");
    Serial.println("[Serial]   help   - show commands");
    Serial.println("[Serial]   status - print capture status");
    Serial.println("[Serial]   stop   - stop capture, save to flash, restore AP");
}

void printCaptureStatus() {
    Serial.printf("[Serial] running=%s raw=%lu target=%lu eapol=%lu pmkid=%lu channel=%u saved_pcap=%u saved_pmkid=%u saved_meta=%u\n",
                  Capture::isRunning ? "yes" : "no",
                  (unsigned long)Capture::getRawChannelFrames(),
                  (unsigned long)Capture::getTargetFrames(),
                  (unsigned long)Capture::eapolCount,
                  (unsigned long)Capture::pmkidCount,
                  Capture::captureChannel,
                  (unsigned)Capture::getLatestPcapSize(),
                  (unsigned)Capture::getLatestPmkidSize(),
                  (unsigned)Capture::getLatestMetaSize());
}

void handleSerialCommand(const String& line) {
    String cmd = line;
    cmd.trim();
    cmd.toLowerCase();
    if (!cmd.length()) return;

    if (cmd == "help" || cmd == "?") {
        printSerialHelp();
        return;
    }

    if (cmd == "status") {
        printCaptureStatus();
        return;
    }

    if (cmd == "stop") {
        if (!Capture::isRunning) {
            Serial.println("[Serial] Capture is not running");
            printCaptureStatus();
            return;
        }
        Serial.println("[Serial] Stopping capture, saving to flash, restoring AP...");
        Capture::stop();
        printCaptureStatus();
        Serial.printf("[Serial] Reconnect to %s and download from the web UI\n", kApSsid);
        return;
    }

    Serial.print("[Serial] Unknown command: ");
    Serial.println(cmd);
    printSerialHelp();
}

void pollSerialCommands() {
    while (Serial.available() > 0) {
        const char ch = static_cast<char>(Serial.read());
        if (ch == '\r') continue;
        if (ch == '\n') {
            handleSerialCommand(gSerialLine);
            gSerialLine = "";
            continue;
        }
        if (gSerialLine.length() < 64) {
            gSerialLine += ch;
        }
    }
}

}  // namespace

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println();
    Serial.printf("[%s] Starting...\n", kProjectName);

    startManagementAp();

    Capture::setup();
    Scanner::setup();
    WebUI::setup();

    Serial.printf("[%s] AP IP: ", kProjectName);
    Serial.println(WiFi.softAPIP());
    Serial.printf("[%s] Ready\n", kProjectName);
    Serial.print("  Connect to '");
    Serial.print(kApSsid);
    Serial.println("'");
    Serial.print("  Open http://");
    Serial.print(WiFi.softAPIP());
    Serial.println("/");
    printSerialHelp();
}

void loop() {
    pollSerialCommands();
    Capture::loop();
    WebUI::loop();
}
