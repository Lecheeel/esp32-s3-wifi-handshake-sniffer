#include "web.h"

#include <cstdio>
#include <cstring>

#include <LittleFS.h>

namespace WebUI {

WebServer server(80);
DNSServer dnsServer;

namespace {

bool streamBufferResponse(const char* contentType, const char* filename, const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return false;
    }

    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Content-Disposition", String("attachment; filename=") + filename);
    server.setContentLength(size);
    server.send(200, contentType, "");

    WiFiClient client = server.client();
    const size_t chunkSize = 1024;
    size_t offset = 0;
    while (offset < size) {
        size_t toWrite = size - offset;
        if (toWrite > chunkSize) toWrite = chunkSize;
        size_t written = client.write(data + offset, toWrite);
        if (written != toWrite) {
            return false;
        }
        offset += written;
        delay(0);
    }
    return true;
}

bool streamFileResponse(const char* path, const char* contentType, const char* filename) {
    File file = LittleFS.open(path, FILE_READ);
    if (!file || file.size() == 0) {
        if (file) file.close();
        return false;
    }

    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Content-Disposition", String("attachment; filename=") + filename);
    server.setContentLength(file.size());
    server.send(200, contentType, "");

    WiFiClient client = server.client();
    uint8_t buffer[1024];
    while (file.available()) {
        size_t n = file.read(buffer, sizeof(buffer));
        if (n == 0) break;
        size_t written = client.write(buffer, n);
        if (written != n) {
            file.close();
            return false;
        }
        delay(0);
    }

    file.close();
    return true;
}

}  // namespace

const char MAIN_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ESP32-S3 WiFi Handshake Sniffer</title>
<style>
:root{--bg:#f5f7fb;--card:#fff;--accent:#0f766e;--accent2:#0ea5e9;--text:#172033;--muted:#63708a;--border:#d9e1ee;--ok:#15803d;--warn:#b45309;--shadow:0 12px 32px rgba(15,23,42,.08)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:linear-gradient(180deg,#eef4ff 0,#f8fbff 180px,#f5f7fb 100%);color:var(--text);padding:18px}
.wrap{max-width:920px;margin:0 auto}
.hero{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:18px}
.hero h1{font-size:1.5rem}
.hero p{color:var(--muted);margin-top:6px}
.pill{padding:8px 12px;border-radius:999px;background:#e6fffb;color:#0f766e;font-size:.84rem;font-weight:700}
.card{background:var(--card);border:1px solid var(--border);border-radius:18px;box-shadow:var(--shadow);padding:20px;margin-bottom:16px}
.card h2{font-size:1.02rem;margin-bottom:14px}
.tip{font-size:.84rem;color:var(--muted);margin-top:-6px;margin-bottom:14px}
.row{display:flex;gap:12px;flex-wrap:wrap}
.col{flex:1;min-width:180px}
label{display:block;font-size:.82rem;color:var(--muted);margin-bottom:6px;font-weight:700}
input,select{width:100%;padding:10px 12px;border:1.5px solid var(--border);border-radius:12px;background:#fbfdff;font-size:.92rem}
button{border:none;border-radius:12px;padding:10px 16px;font-weight:700;cursor:pointer}
.primary{background:var(--accent);color:#fff}
.ghost{background:#ecfeff;color:#0f766e}
.danger{background:#fee2e2;color:#b91c1c}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
table{width:100%;border-collapse:collapse;font-size:.87rem}
th,td{padding:10px 8px;border-bottom:1px solid var(--border);text-align:left}
th{color:var(--muted);font-size:.76rem;text-transform:uppercase}
.mono{font-family:Consolas,monospace}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.stat{background:#f7fafc;border:1px solid var(--border);border-radius:14px;padding:14px;text-align:center}
.stat strong{display:block;font-size:1.35rem;color:var(--accent2)}
.status{font-weight:700}
.hint{margin-top:10px;font-size:.82rem;color:var(--warn)}
.overlay{position:fixed;inset:0;background:rgba(15,23,42,.72);display:none;align-items:center;justify-content:center;padding:18px;z-index:20}
.overlay.show{display:flex}
.dialog{max-width:420px;width:100%;background:#fff;border-radius:20px;padding:24px;box-shadow:0 20px 50px rgba(15,23,42,.22);text-align:center}
.dialog h3{font-size:1.15rem;margin-bottom:10px}
.dialog p{color:var(--muted);line-height:1.6}
.count{font-size:2.4rem;font-weight:800;color:var(--accent2);margin:14px 0}
@media(max-width:640px){body{padding:10px}.hero{flex-direction:column}.card{padding:16px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div>
      <h1>ESP32-S3 WiFi Handshake Sniffer</h1>
      <p>仅用于被动监听握手包 / PMKID。启动抓包后，管理热点会暂时断开，停止后恢复。</p>
    </div>
    <div class="pill" id="apState">管理热点在线</div>
  </div>

  <div class="card">
    <h2>WiFi 扫描</h2>
    <div class="actions">
      <button class="primary" id="scanBtn" onclick="scanNetworks()">扫描附近 AP</button>
      <span class="tip" id="scanStatus"></span>
    </div>
    <div style="overflow:auto;margin-top:12px">
      <table>
        <thead><tr><th>SSID</th><th>BSSID</th><th>RSSI</th><th>信道</th><th>加密</th><th></th></tr></thead>
        <tbody id="scanBody"><tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:20px">点击扫描加载周边网络</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2>被动抓包</h2>
    <div class="tip">建议先选择目标 AP，再固定目标信道监听。全信道模式会保存更多包，但噪声更高。</div>
    <div class="row">
      <div class="col">
        <label>抓取模式</label>
        <select id="capMode" onchange="toggleMode()">
          <option value="target">目标 BSSID 过滤</option>
          <option value="full">整信道监听</option>
        </select>
      </div>
      <div class="col" id="bssidCol">
        <label>目标 BSSID</label>
        <input id="capBssid" maxlength="17" placeholder="AA:BB:CC:DD:EE:FF">
      </div>
      <div class="col">
        <label>监听信道</label>
        <input id="capChannel" type="number" min="1" max="14" value="1">
      </div>
    </div>
    <div class="actions">
      <button class="primary" id="startBtn" onclick="captureStart()">开始监听</button>
      <button class="danger" id="stopBtn" onclick="captureStop()" disabled>停止监听</button>
      <button class="ghost" id="pcapBtn" onclick="downloadPcap()" disabled>下载 .pcap</button>
      <button class="ghost" id="pmkidBtn" onclick="downloadPmkid()" disabled>下载 .22000</button>
    </div>
    <div class="hint">抓包开始后 Web 页面可能短暂断开；停止监听后重新连接 `esp32-s3-wifi-handshake-sniffer` 即可。</div>
    <div class="tip" id="latestHint">最近一次抓包会在停止监听后自动保存到设备 Flash。</div>
  </div>

  <div class="card">
    <h2>抓取状态</h2>
    <div class="stats">
      <div class="stat"><span>状态</span><strong id="capStatus" class="status">空闲</strong></div>
      <div class="stat"><span>目标帧</span><strong id="capFrames">0</strong></div>
      <div class="stat"><span>信道原始帧</span><strong id="capRawFrames">0</strong></div>
      <div class="stat"><span>EAPOL</span><strong id="capEapol">0</strong></div>
      <div class="stat"><span>PMKID</span><strong id="capPmkid">0</strong></div>
      <div class="stat"><span>摘要</span><strong id="capSummary" style="font-size:.92rem">idle</strong></div>
    </div>
  </div>

  <div class="card">
    <h2>已保存抓包</h2>
    <div class="tip">只有在停止监听后，当前会话才会保存到设备 Flash。这里显示的是最近一次已保存结果。</div>
    <div class="stats">
      <div class="stat"><span>PCAP</span><strong id="savedPcapSize">0 B</strong></div>
      <div class="stat"><span>22000</span><strong id="savedPmkidSize">0 B</strong></div>
      <div class="stat"><span>报告</span><strong id="savedMetaSize">0 B</strong></div>
      <div class="stat"><span>保存状态</span><strong id="savedState" style="font-size:.92rem">无</strong></div>
    </div>
    <div class="actions">
      <button class="ghost" id="savedPcapBtn" onclick="downloadSavedPcap()" disabled>下载已保存 .pcap</button>
      <button class="ghost" id="savedPmkidBtn" onclick="downloadSavedPmkid()" disabled>下载已保存 .22000</button>
      <button class="ghost" id="savedMetaBtn" onclick="downloadSavedMeta()" disabled>下载报告 .json</button>
      <button class="danger" id="clearSavedBtn" onclick="clearSaved()" disabled>清除已保存</button>
    </div>
  </div>
</div>
<div class="overlay" id="countdownOverlay">
  <div class="dialog">
    <h3>即将进入监听模式</h3>
    <p>管理热点会暂时关闭，当前网页连接将中断。停止监听后，重新连接 <strong>esp32-s3-wifi-handshake-sniffer</strong> 查看结果。</p>
    <div class="count" id="countdownValue">3</div>
    <div class="actions" style="justify-content:center">
      <button class="danger" type="button" onclick="cancelCountdown()">取消</button>
    </div>
  </div>
</div>
<script>
function $(id){return document.getElementById(id)}
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
function encMap(v){var m={0:'开放',1:'WEP',2:'WPA',3:'WPA2',4:'WPA/WPA2',5:'WPA2-企业',6:'WPA3',7:'WPA2/3'};return m[v]||('#'+v)}
let countdownTimer=null;
let pendingCaptureBody=null;

window.addEventListener('DOMContentLoaded',()=>{toggleMode();pollStatus();setInterval(pollStatus,2000)})

function toggleMode(){
  $('bssidCol').style.display=$('capMode').value==='full'?'none':'block'
}

async function scanNetworks(){
  $('scanBtn').disabled=true;$('scanStatus').textContent='扫描中...';
  try{
    const r=await fetch('/api/scan');const d=await r.json();renderTable(d);$('scanStatus').textContent=''
  }catch(e){$('scanStatus').textContent='扫描失败'}
  $('scanBtn').disabled=false
}

function renderTable(nets){
  const body=$('scanBody');
  if(!nets||!nets.length){body.innerHTML='<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:20px">未发现 AP</td></tr>';return}
  let h='';
  nets.forEach(n=>{
    h+='<tr>';
    h+='<td>'+esc(n.ssid||'<hidden>')+'</td>';
    h+='<td class="mono">'+esc(n.bssid||'')+'</td>';
    h+='<td>'+(n.rssi??'')+'</td>';
    h+='<td>'+(n.channel??'')+'</td>';
    h+='<td>'+esc(encMap(n.encryption))+'</td>';
    h+='<td><button class="ghost" type="button" data-bssid="'+esc(n.bssid||'')+'" data-channel="'+(n.channel||1)+'">选择</button></td>';
    h+='</tr>';
  });
  body.innerHTML=h
}

document.addEventListener('click',e=>{
  const btn=e.target.closest('button[data-bssid]');
  if(!btn)return;
  $('capBssid').value=btn.dataset.bssid||'';
  $('capChannel').value=btn.dataset.channel||'1';
  $('capMode').value='target';
  toggleMode();
})

async function captureStart(){
  const mode=$('capMode').value;
  const bssid=$('capBssid').value.trim();
  const channel=parseInt($('capChannel').value,10)||1;
  if(mode!=='full'&&!bssid){alert('请输入目标 BSSID');return}
  pendingCaptureBody={mode:mode,bssid:bssid,channel:channel};
  beginCountdown()
}

function beginCountdown(){
  cancelCountdown(false);
  let remaining=3;
  $('countdownValue').textContent=String(remaining);
  $('countdownOverlay').classList.add('show');
  countdownTimer=setInterval(async()=>{
    remaining--;
    $('countdownValue').textContent=String(remaining);
    if(remaining<=0){
      cancelCountdown(false);
      await startCaptureRequest();
    }
  },1000)
}

function cancelCountdown(clearPending=true){
  if(countdownTimer){clearInterval(countdownTimer);countdownTimer=null}
  $('countdownOverlay').classList.remove('show');
  if(clearPending)pendingCaptureBody=null
}

async function startCaptureRequest(){
  if(!pendingCaptureBody)return;
  try{
    const r=await fetch('/api/capture/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(pendingCaptureBody)});
    const d=await r.json();
    if(d.status==='ok'){
      $('startBtn').disabled=true;$('stopBtn').disabled=false;$('capStatus').textContent='监听中'
    }else if(d.msg){alert(d.msg)}
  }catch(e){console.error(e)}
  pendingCaptureBody=null
}

async function captureStop(){
  try{
    const r=await fetch('/api/capture/stop',{method:'POST'});
    const d=await r.json();
    if(d.status==='ok'){
      $('startBtn').disabled=false;$('stopBtn').disabled=true;$('capStatus').textContent='已停止'
    }
  }catch(e){console.error(e)}
}

function downloadPcap(){window.open('/api/capture/download','_blank')}
function downloadPmkid(){window.open('/api/capture/pmkid','_blank')}
function downloadSavedPcap(){window.open('/api/capture/download?source=latest','_blank')}
function downloadSavedPmkid(){window.open('/api/capture/pmkid?source=latest','_blank')}
function downloadSavedMeta(){window.open('/api/capture/meta','_blank')}

async function clearSaved(){
  try{
    const r=await fetch('/api/capture/clear',{method:'POST'});
    const d=await r.json();
    if(d.status==='ok'){pollStatus()}
  }catch(e){console.error(e)}
}

function fmtSize(n){
  n=Number(n||0);
  if(n<1024)return n+' B';
  if(n<1024*1024)return (n/1024).toFixed(1)+' KB';
  return (n/1024/1024).toFixed(2)+' MB';
}

async function pollStatus(){
  try{
    const r=await fetch('/api/capture/status');const d=await r.json();
    $('capStatus').textContent=d.running?'监听中':'空闲';
    $('capFrames').textContent=d.frames||0;
    $('capRawFrames').textContent=d.rawFrames||0;
    $('capEapol').textContent=d.eapol||0;
    $('capPmkid').textContent=d.pmkidCount||0;
    $('capSummary').textContent=d.summary||'idle';
    $('startBtn').disabled=!!d.running;
    $('stopBtn').disabled=!d.running;
    $('pcapBtn').disabled=!(!d.running && ((d.size||0)>24 || (d.latestPcapSize||0)>24));
    $('pmkidBtn').disabled=!((d.pmkidSize||0)>0 || (d.latestPmkidSize||0)>0);
    $('savedPcapSize').textContent=fmtSize(d.latestPcapSize||0);
    $('savedPmkidSize').textContent=fmtSize(d.latestPmkidSize||0);
    $('savedMetaSize').textContent=fmtSize(d.latestMetaSize||0);
    $('savedState').textContent=(d.latestPcapSize||0)>24 || (d.latestPmkidSize||0)>0 || (d.latestMetaSize||0)>0 ? '有已保存结果' : '无';
    $('savedPcapBtn').disabled=!((d.latestPcapSize||0)>24);
    $('savedPmkidBtn').disabled=!((d.latestPmkidSize||0)>0);
    $('savedMetaBtn').disabled=!((d.latestMetaSize||0)>0);
    $('clearSavedBtn').disabled=!((d.latestPcapSize||0)>0 || (d.latestPmkidSize||0)>0 || (d.latestMetaSize||0)>0);
    $('apState').textContent=d.apActive?'管理热点在线':'监听模式中';
    if(!d.running&&(d.latestPcapSize||0)>24){$('latestHint').textContent='最近一次抓包已保存在设备 Flash，可直接下载。'}
    else{$('latestHint').textContent='最近一次抓包会在停止监听后自动保存到设备 Flash。'}
  }catch(e){}
}
</script>
</body>
</html>
)rawliteral";

static int parseJsonInt(const String& body, const char* key, int defaultVal) {
    String search = "\"" + String(key) + "\":";
    int pos = body.indexOf(search);
    if (pos < 0) return defaultVal;
    pos += search.length();
    while (pos < (int)body.length() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
    return body.substring(pos).toInt();
}

static String parseJsonString(const String& body, const char* key, const char* defaultVal) {
    String search = "\"" + String(key) + "\":\"";
    int pos = body.indexOf(search);
    if (pos < 0) return String(defaultVal);
    pos += search.length();
    int end = body.indexOf('"', pos);
    if (end < 0) return String(defaultVal);
    return body.substring(pos, end);
}

static bool parseMacString(const char* str, uint8_t out[6]) {
    if (!str || strlen(str) != 17) return false;
    int values[6];
    int n = sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x",
                   &values[0], &values[1], &values[2],
                   &values[3], &values[4], &values[5]);
    if (n != 6) return false;
    for (int i = 0; i < 6; ++i) out[i] = (uint8_t)values[i];
    return true;
}

static String jsonEscape(const char* input) {
    String out;
    if (!input) return out;
    for (const char* p = input; *p; ++p) {
        switch (*p) {
            case '\"': out += F("\\\""); break;
            case '\\': out += F("\\\\"); break;
            case '\n': out += F("\\n"); break;
            case '\r': out += F("\\r"); break;
            case '\t': out += F("\\t"); break;
            default: out += *p; break;
        }
    }
    return out;
}

static void sendJson(int code, const String& body) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(code, "application/json", body);
}

static void handleRoot() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send_P(200, "text/html", MAIN_PAGE);
}

static void handleScan() {
    sendJson(200, Scanner::scanToJson());
}

static void handleCaptureStart() {
    String mode = "target";
    String bssidStr = "";
    int channel = 1;

    if (server.hasArg("plain")) {
        String body = server.arg("plain");
        mode = parseJsonString(body, "mode", "target");
        bssidStr = parseJsonString(body, "bssid", "");
        channel = parseJsonInt(body, "channel", 1);
    }

    if (channel < 1) channel = 1;
    if (channel > 14) channel = 14;

    uint8_t bssid[6];
    bool fullMode = (mode == "full");
    if (!fullMode && !parseMacString(bssidStr.c_str(), bssid)) {
        sendJson(400, "{\"status\":\"error\",\"msg\":\"invalid bssid\"}");
        return;
    }

    Capture::start((uint8_t)channel, fullMode ? nullptr : bssid, fullMode);
    if (!Capture::isRunning) {
        String msg = Capture::getLastError();
        if (!msg.length()) msg = "capture start failed";
        sendJson(400, String("{\"status\":\"error\",\"msg\":\"") + jsonEscape(msg.c_str()) + "\"}");
        return;
    }

    sendJson(200, "{\"status\":\"ok\"}");
}

static void handleCaptureStop() {
    Capture::stop();
    sendJson(200, "{\"status\":\"ok\"}");
}

static void handleCaptureStatus() {
    char buf[768];
    snprintf(buf, sizeof(buf),
             "{\"running\":%s,\"handshake\":%s,\"pmkid\":%s,\"frames\":%lu,"
             "\"rawFrames\":%lu,\"eapol\":%lu,\"pmkidCount\":%lu,\"channel\":%u,\"fullMode\":%s,"
             "\"summary\":\"%s\",\"size\":%u,\"pmkidSize\":%u,\"apActive\":%s,"
             "\"latestPcapSize\":%u,\"latestPmkidSize\":%u,\"latestMetaSize\":%u}",
             Capture::isRunning ? "true" : "false",
             Capture::handshakeFound ? "true" : "false",
             Capture::pmkidFound ? "true" : "false",
             (unsigned long)Capture::frameCount,
             (unsigned long)Capture::getRawChannelFrames(),
             (unsigned long)Capture::eapolCount,
             (unsigned long)Capture::pmkidCount,
             Capture::captureChannel,
             Capture::usesFullChannel() ? "true" : "false",
             Capture::getCaptureSummary(),
             (unsigned)Capture::getPcapSize(),
             (unsigned)Capture::getPmkidSize(),
             Capture::managementApActive() ? "true" : "false",
             (unsigned)Capture::getLatestPcapSize(),
             (unsigned)Capture::getLatestPmkidSize(),
             (unsigned)Capture::getLatestMetaSize());
    sendJson(200, String(buf));
}

static void handleCaptureDownload() {
    if (Capture::isRunning) {
        sendJson(409, "{\"status\":\"error\",\"msg\":\"stop capture before downloading\"}");
        return;
    }

    if (Capture::getLatestPcapSize() <= 24) {
        sendJson(404, "{\"status\":\"error\",\"msg\":\"no data\"}");
        return;
    }
    if (!streamFileResponse("/latest_capture.pcap", "application/vnd.tcpdump.pcap", "latest_capture.pcap")) {
        sendJson(500, "{\"status\":\"error\",\"msg\":\"saved pcap stream failed\"}");
    }
}

static void handlePmkidDownload() {
    bool latestOnly = server.hasArg("source") && server.arg("source") == "latest";
    size_t size = Capture::getPmkidSize();
    if (!latestOnly && size > 0) {
        server.sendHeader("Access-Control-Allow-Origin", "*");
        server.sendHeader("Content-Disposition", "attachment; filename=pmkid.22000");
        server.send(200, "text/plain", Capture::getPmkidData());
        return;
    }
    String latest;
    if (!Capture::loadLatestPmkid(latest) || latest.length() == 0) {
        sendJson(404, "{\"status\":\"error\",\"msg\":\"no pmkid\"}");
        return;
    }
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Content-Disposition", "attachment; filename=latest_capture.22000");
    server.send(200, "text/plain", latest);
}

static void handleMetaDownload() {
    String latest;
    if (!Capture::loadLatestMeta(latest) || latest.length() == 0) {
        sendJson(404, "{\"status\":\"error\",\"msg\":\"no saved report\"}");
        return;
    }
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Content-Disposition", "attachment; filename=latest_capture.json");
    server.send(200, "application/json", latest);
}

static void handleClearSaved() {
    bool ok = Capture::clearLatestSaved();
    sendJson(ok ? 200 : 500, ok ? "{\"status\":\"ok\"}" : "{\"status\":\"error\",\"msg\":\"clear failed\"}");
}

static void handleCors() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
    server.send(204);
}

static void handleNoContent() {
    server.send(204);
}

void setup() {
    dnsServer.start(53, "*", WiFi.softAPIP());

    server.on("/", HTTP_GET, handleRoot);
    server.on("/api/scan", HTTP_GET, handleScan);
    server.on("/api/capture/start", HTTP_POST, handleCaptureStart);
    server.on("/api/capture/stop", HTTP_POST, handleCaptureStop);
    server.on("/api/capture/status", HTTP_GET, handleCaptureStatus);
    server.on("/api/capture/download", HTTP_GET, handleCaptureDownload);
    server.on("/api/capture/pmkid", HTTP_GET, handlePmkidDownload);
    server.on("/api/capture/meta", HTTP_GET, handleMetaDownload);
    server.on("/api/capture/clear", HTTP_POST, handleClearSaved);

    server.on("/api/capture/start", HTTP_OPTIONS, handleCors);
    server.on("/api/capture/stop", HTTP_OPTIONS, handleCors);
    server.on("/api/capture/clear", HTTP_OPTIONS, handleCors);

    server.on("/generate_204", HTTP_GET, handleRoot);
    server.on("/hotspot-detect.html", HTTP_GET, handleRoot);
    server.on("/canonical.html", HTTP_GET, handleRoot);
    server.on("/ncsi.txt", HTTP_GET, handleRoot);
    server.on("/success.txt", HTTP_GET, handleRoot);
    server.on("/redirect", HTTP_GET, handleRoot);
    server.on("/fwlink", HTTP_GET, handleRoot);
    server.on("/favicon.ico", HTTP_GET, handleNoContent);
    server.on("/apple-touch-icon.png", HTTP_GET, handleNoContent);
    server.on("/apple-touch-icon-precomposed.png", HTTP_GET, handleNoContent);
    server.on("/connecttest.txt", HTTP_GET, handleRoot);
    server.on("/library/test/success.html", HTTP_GET, handleRoot);
    server.on("/hotspotdetect.html", HTTP_GET, handleRoot);
    server.on("/", HTTP_HEAD, handleNoContent);
    server.onNotFound(handleNoContent);

    server.begin();
}

void loop() {
    dnsServer.processNextRequest();
    server.handleClient();
}

}  // namespace WebUI
