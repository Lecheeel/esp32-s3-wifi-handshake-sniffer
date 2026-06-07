# ESP32-S3 WiFi Handshake Sniffer

## 中文简介

ESP32-S3 WiFi Handshake Sniffer 是一个基于 ESP32-S3、PlatformIO 和 Arduino 框架的 WiFi 握手包 / PMKID 被动监听工具。设备启动后会创建本地管理热点，并提供一个中文 Web UI，用于扫描附近 AP、选择目标 BSSID 和信道、启动监听、查看抓取状态，并下载抓取结果。

本项目适合用于授权 WiFi 安全测试、实验室研究和学习 802.11 WPA/WPA2 握手流程。请仅在你拥有或明确获得授权的网络环境中使用。

## 功能特性

- 支持 ESP32-S3 DevKitC-1
- 使用 PlatformIO + Arduino 开发
- 启动本地管理 AP，并通过 Captive Portal 风格 Web UI 操作
- 扫描附近 WiFi，显示 SSID、BSSID、RSSI、信道和加密类型
- 支持目标 BSSID 过滤模式
- 支持整信道监听模式
- 被动监听 EAPOL 握手包
- 检测 WPA/WPA2 四次握手进度
- 提取 PMKID，并导出 hashcat `.22000` 格式
- 导出带 Radiotap 头的 `.pcap` 文件
- 将最近一次抓包的 PCAP、PMKID 和 JSON 元数据保存到 LittleFS
- 支持串口命令查看状态和停止抓包

## 硬件与环境

- ESP32-S3 DevKitC-1
- PlatformIO
- Arduino framework for ESP32

默认工程配置见 `platformio.ini`：

```ini
[env:esp32-s3-devkitc-1]
platform = espressif32
board = esp32-s3-devkitc-1
framework = arduino
monitor_speed = 115200
upload_speed = 921600
board_build.flash_mode = qio
```

## 使用方法

1. 使用 PlatformIO 编译并烧录固件。
2. 打开串口监视器，等待设备启动。
3. 连接设备创建的 WiFi 热点：

```text
esp32-s3-wifi-handshake-sniffer
```

4. 打开设备管理页面，默认地址通常为：

```text
http://192.168.4.1/
```

5. 在 Web UI 中扫描附近 AP，选择目标网络，开始监听。
6. 抓包开始后管理热点会临时关闭，Web 页面可能断开。
7. 停止监听后重新连接管理热点，在 Web UI 中下载 `.pcap`、`.22000` 或 `.json` 报告。

## 串口命令

```text
help   - 显示命令列表
status - 输出当前抓包状态
stop   - 停止抓包，保存结果，并恢复管理热点
```

## 输出文件

- `latest_capture.pcap`：最近一次抓包结果，可用于 Wireshark 等工具分析
- `latest_capture.22000`：PMKID hashcat 22000 格式输出
- `latest_capture.json`：抓包会话元数据，包括信道、帧数量、EAPOL/PMKID 数量和耗时等

## 注意事项

- ESP32-S3 监听时需要固定在目标信道。
- 目标网络需要有客户端重连或产生握手相关流量，才能抓到 EAPOL 握手。
- 全信道监听模式实际是监听当前配置的单个信道上的全部匹配帧，不会自动跳频。
- 抓包期间管理 AP 会关闭，停止抓包后才会恢复。
- 本项目不会主动发送解除认证帧，只做被动监听。

## English Overview

ESP32-S3 WiFi Handshake Sniffer is a lightweight WiFi handshake and PMKID sniffer built for ESP32-S3 with PlatformIO and the Arduino framework. The device starts a local management access point with a browser-based Web UI for AP scanning, target selection, passive monitor-mode capture, status tracking, and result downloads.

This project is intended for authorized WiFi security testing, lab research, and learning 802.11 WPA/WPA2 handshake behavior. Use it only on networks you own or have explicit permission to test.

## Features

- ESP32-S3 DevKitC-1 support
- PlatformIO + Arduino project
- Built-in management AP with captive-portal-style Web UI
- Nearby AP scanning with SSID, BSSID, RSSI, channel, and encryption info
- Target BSSID capture mode
- Full current-channel monitor mode
- Passive EAPOL handshake detection
- WPA/WPA2 four-way handshake progress tracking
- PMKID extraction with hashcat `.22000` export
- `.pcap` export with Radiotap headers
- Latest PCAP, PMKID, and JSON metadata saved to LittleFS
- Serial commands for status, stop, and help

## Build And Flash

Install PlatformIO, connect your ESP32-S3 DevKitC-1, then build and upload:

```sh
pio run
pio run --target upload
pio device monitor
```

## Repository Topics

Suggested GitHub topics:

```text
esp32-s3
wifi
sniffer
handshake
pmkid
eapol
pcap
hashcat
platformio
arduino
littlefs
wifi-security
```

## License

No license has been selected yet. Add a license before publishing if you want to define how others may use this project.
