#include <Arduino.h>
#include <SPI.h>
#include <WiFi.h>
#include <Preferences.h>
#include <SD.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <XPT2046_Touchscreen.h>
#include <math.h>

// BLE adds roughly 1 MB to the classic ESP32 binary. Keep it disabled for
// the default 1.3 MB application partition. Set this to 1 only when using
// Tools > Partition Scheme > Huge APP (3MB No OTA/1MB SPIFFS).
#define KRNL_ENABLE_BLE 0

#if KRNL_ENABLE_BLE
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#endif

// ================================================================
// KRNL firmware v0.3
// Target: classic ESP32 + ILI9341 + XPT2046 + microSD + TSOP1838B
// Scope: passive Wi-Fi reconnaissance, management monitoring and IR diagnostics
// ================================================================

// ---------------------------- Pins -------------------------------

constexpr uint8_t PIN_SPI_SCK  = 18;
constexpr uint8_t PIN_SPI_MISO = 19;
constexpr uint8_t PIN_SPI_MOSI = 23;

constexpr uint8_t PIN_TFT_CS  = 27;
constexpr uint8_t PIN_TFT_DC  = 26;
constexpr uint8_t PIN_TFT_RST = 25;

constexpr uint8_t PIN_TOUCH_CS  = 33;
constexpr uint8_t PIN_TOUCH_IRQ = 32;

// SD shares SCK/MISO/MOSI with the display and touch controller.
constexpr uint8_t PIN_SD_CS = 13;

// TSOP1838B demodulated 38 kHz IR receiver output (active LOW).
constexpr uint8_t PIN_IR_RECEIVER = 21;

// -------------------------- UI constants -------------------------

constexpr int16_t SCREEN_W = 320;
constexpr int16_t SCREEN_H = 240;
constexpr int16_t HEADER_H = 25;
constexpr int16_t NAV_Y = 212;

constexpr uint16_t C_BG       = ILI9341_BLACK;
constexpr uint16_t C_PANEL    = 0x0841;
constexpr uint16_t C_GRID     = 0x18E3;
constexpr uint16_t C_CYAN     = ILI9341_CYAN;
constexpr uint16_t C_DARKCYAN = ILI9341_DARKCYAN;
constexpr uint16_t C_GREEN    = ILI9341_GREEN;
constexpr uint16_t C_YELLOW   = ILI9341_YELLOW;
constexpr uint16_t C_ORANGE   = 0xFD20;
constexpr uint16_t C_RED      = ILI9341_RED;
constexpr uint16_t C_WHITE    = ILI9341_WHITE;
constexpr uint16_t C_GREY     = 0x8410;

constexpr uint8_t MAX_APS = 40;
constexpr uint8_t MAX_LOGS = 30;
constexpr uint8_t RECON_ROWS = 5;
constexpr uint8_t SD_LOG_QUEUE_LINES = 16;
constexpr uint8_t SD_LOG_LINE_LENGTH = 128;
constexpr uint8_t RSSI_HISTORY_SAMPLES = 16;
constexpr uint8_t MAX_WATCHLIST = 8;
constexpr uint32_t IR_BURST_END_US = 50000UL;
constexpr uint8_t MONITOR_QUEUE_LENGTH = 12;
constexpr uint16_t MONITOR_SNAPLEN = 128;
constexpr uint32_t MONITOR_HOP_INTERVAL_MS = 700UL;

Adafruit_ILI9341 tft(&SPI, PIN_TFT_DC, PIN_TFT_CS, PIN_TFT_RST);
XPT2046_Touchscreen touch(PIN_TOUCH_CS, PIN_TOUCH_IRQ);
Preferences prefs;

enum Screen : uint8_t {
  HOME,
  RECON,
  DETAILS,
  LOGS,
  TOOLS,
  SETTINGS
};

enum K17Mood : uint8_t {
  K17_IDLE,
  K17_SCANNING,
  K17_DONE,
  K17_ERROR,
  K17_INSPECT
};

struct AccessPoint {
  char ssid[33];
  char bssid[18];
  int32_t rssi;
  uint8_t channel;
  uint8_t auth;
  uint16_t sightings;
  uint16_t channelChanges;
  uint16_t securityChanges;
  uint8_t missedScans;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint32_t lastChange;
  uint8_t lastAlertScore;
  int8_t rssiHistory[RSSI_HISTORY_SAMPLES];
  uint8_t historyHead;
  uint8_t historyCount;
  bool active;
  bool hidden;
};

struct BLERecord {
  char name[22];
  char address[18];
  int16_t rssi;
};

struct LogEntry {
  uint32_t timestamp;
  char category[9];
  char message[65];
};

struct TouchCalibration {
  int32_t x0 = 200;
  int32_t x1 = 3900;
  int32_t y0 = 200;
  int32_t y1 = 3900;
  bool swapXY = false;
};

struct MonitorFrame {
  uint32_t timestampUs;
  uint16_t originalLength;
  uint16_t capturedLength;
  int8_t rssi;
  uint8_t channel;
  uint8_t subtype;
  uint16_t reasonCode;
  uint8_t transmitter[6];
  uint8_t bssid[6];
  bool saveToPcap;
  uint8_t bytes[MONITOR_SNAPLEN];
};

struct __attribute__((packed)) PcapGlobalHeader {
  uint32_t magic;
  uint16_t major;
  uint16_t minor;
  int32_t timezone;
  uint32_t timestampAccuracy;
  uint32_t snapLength;
  uint32_t linkType;
};

struct __attribute__((packed)) PcapRecordHeader {
  uint32_t seconds;
  uint32_t microseconds;
  uint32_t includedLength;
  uint32_t originalLength;
};

AccessPoint apCache[MAX_APS];
LogEntry logBuffer[MAX_LOGS];
BLERecord bleRecords[10];
uint8_t sortedAP[MAX_APS];
char sdLogQueue[SD_LOG_QUEUE_LINES][SD_LOG_LINE_LENGTH];
char watchedBSSIDs[MAX_WATCHLIST][18];
char baselineBSSIDs[MAX_APS][18];

uint8_t apCount = 0;
uint8_t visibleAPCount = 0;
uint8_t logCount = 0;
uint8_t logHead = 0;
int16_t selectedAP = -1;
uint8_t reconPage = 0;

Screen currentScreen = HOME;
TouchCalibration calibration;

bool autoScan = true;
bool showHidden = true;
bool scanRunning = false;
bool uiDirty = true;
bool fullRedraw = true;
bool touchLatched = false;
bool clockConfigured = false;
bool calibrationValid = false;
bool radioPowerSave = false;
bool bleInitialized = false;
bool sdReady = false;
bool sdWriteError = false;
bool accessPinConfigured = false;
bool adaptiveScan = true;
bool guardMode = true;
bool baselineReady = false;
bool monitorActive = false;
bool monitorChannelHop = true;

uint8_t toolsMode = 0;       // 0 radar, 1 channels, 2 diagnostics, 3 IR, 4 packets
uint8_t settingsPage = 0;
uint8_t detailsPage = 0;
uint8_t bleDeviceCount = 0;
uint8_t watchlistCount = 0;
uint8_t stableScanCount = 0;
uint8_t scanEventCount = 0;
uint8_t baselineCount = 0;
uint8_t baselineLearningScans = 0;
uint8_t monitorChannel = 1;
uint8_t sdLogQueueHead = 0;
uint8_t sdLogQueueTail = 0;
uint8_t sdLogQueueCount = 0;
K17Mood k17Mood = K17_IDLE;
uint8_t k17Frame = 0;

uint32_t scanIntervalMs = 10000;
uint32_t nextScanAt = 1000;
uint32_t lastTouchAt = 0;
uint32_t lastHeaderUpdate = 0;
uint32_t scanStartedAt = 0;
uint32_t lastScanDurationMs = 0;
uint32_t completedScans = 0;
uint16_t scanFailureCount = 0;
uint16_t sdSessionId = 0;
uint32_t lastSDFlushAt = 0;
uint32_t sdBytesWritten = 0;
uint32_t accessPinHash = 0;
uint32_t simulatedIncidentCount = 0;
uint32_t irBurstCount = 0;
uint32_t lastIRBurstAt = 0;
uint32_t lastIREdges = 0;
uint32_t lastIRMinLowUs = 0;
uint32_t lastIRMaxLowUs = 0;
uint32_t lastIRMinHighUs = 0;
uint32_t lastIRMaxHighUs = 0;
uint32_t monitorFrames = 0;
uint32_t monitorBeacons = 0;
uint32_t monitorProbeRequests = 0;
uint32_t monitorProbeResponses = 0;
uint32_t monitorDeauth = 0;
uint32_t monitorDisassoc = 0;
volatile uint32_t monitorDropped = 0;
uint32_t monitorPacketsPerSecond = 0;
uint32_t monitorPpsAccumulator = 0;
uint32_t monitorPpsWindowAt = 0;
uint32_t lastMonitorHopAt = 0;
uint32_t lastMonitorUIAt = 0;
uint32_t lastDisruptionLogAt = 0;
uint16_t monitorCaptureId = 0;
int8_t lastMonitorRSSI = 0;
uint8_t lastMonitorSubtype = 0;
uint8_t lastMonitorChannel = 0;
uint16_t lastMonitorReason = 0;
char lastMonitorTransmitter[18] = "--:--:--:--:--:--";
char lastMonitorBSSID[18] = "--:--:--:--:--:--";
char monitorCapturePath[48] = {0};
char sdLogPath[40] = {0};
char sdScanPath[40] = {0};
uint32_t lastRadarUpdate = 0;
uint32_t lastK17Update = 0;
uint32_t lastLogsWaveUpdate = 0;
uint32_t clockBaseSeconds = 0;
uint32_t clockSetAtMillis = 0;
float radarSweepAngle = 0.0f;
float previousRadarSweepAngle = 0.0f;

volatile uint32_t irEdgeCount = 0;
volatile uint32_t irLastEdgeAtUs = 0;
volatile uint32_t irShortestLowUs = UINT32_MAX;
volatile uint32_t irLongestLowUs = 0;
volatile uint32_t irShortestHighUs = UINT32_MAX;
volatile uint32_t irLongestHighUs = 0;
QueueHandle_t monitorQueue = nullptr;

// ---------------------- Forward declarations ---------------------

void renderScreen();
void startScan();
void finishScan(int16_t resultCount);
void runCalibration();
void runTimeEditor();
void serviceRadarAnimation();
void serviceK17Animation();
void serviceLogsWaveform();
void runBLEScan();
void serviceIRReceiver();
void drawIRMonitor();
void appendIREvent();
bool startPacketMonitor();
void stopPacketMonitor();
void servicePacketMonitor();
void drawPacketMonitor();
void appendMonitorEvent(const MonitorFrame& frame, const char* eventName);
bool initializeSD();
void enqueueSDLog(const char* line);
void flushSDLogs(bool force = false);
void appendScanCSV();
void writeLatestSnapshot();
void appendScanSummary(int16_t resultCount);
void appendAnomalyArchive();
void appendSecurityAudit(const char* event);
void writeConfigBackup();
const char* authName(uint8_t auth);
void formatClock(char* output, size_t size);
uint8_t anomalyScore(uint8_t cacheIndex);
uint8_t countOpenNetworks();
uint8_t warningCount();
bool hasSecurityMismatch(uint8_t cacheIndex);
bool isWatchedBSSID(const char* bssid);
void toggleWatchlist(const char* bssid);
void simulateGuardIncident();
bool isInBaseline(const char* bssid);
void loadBaseline();
void saveBaseline();
void resetBaseline();
void configureOrUnlock();
bool verifyAccessPin(const char* title);
void wipeKRNLData();
bool confirmKRNLWipe();

// -------------------------- IR receiver --------------------------

void IRAM_ATTR handleIREdge() {
  uint32_t now = micros();
  bool currentLevel = digitalRead(PIN_IR_RECEIVER);

  if (irLastEdgeAtUs != 0) {
    uint32_t duration = now - irLastEdgeAtUs;
    // At a transition, the previous level is the inverse of the new level.
    if (currentLevel) {
      if (duration < irShortestLowUs) irShortestLowUs = duration;
      if (duration > irLongestLowUs) irLongestLowUs = duration;
    } else {
      if (duration < irShortestHighUs) irShortestHighUs = duration;
      if (duration > irLongestHighUs) irLongestHighUs = duration;
    }
  }

  irEdgeCount++;
  irLastEdgeAtUs = now;
}

void wifiMonitorCallback(void* buffer, wifi_promiscuous_pkt_type_t packetType) {
  if (!monitorActive || !monitorQueue || packetType != WIFI_PKT_MGMT || !buffer) return;

  const wifi_promiscuous_pkt_t* packet =
      static_cast<const wifi_promiscuous_pkt_t*>(buffer);
  uint16_t length = packet->rx_ctrl.sig_len;
  if (length < 24) return;

  const uint8_t* payload = packet->payload;
  uint16_t frameControl = payload[0] | (static_cast<uint16_t>(payload[1]) << 8);
  uint8_t frameType = (frameControl >> 2) & 0x03;
  uint8_t subtype = (frameControl >> 4) & 0x0F;
  if (frameType != 0) return;

  // Retain only useful management types: probe request/response, beacon,
  // disassociation and deauthentication. Data/control payloads never enter
  // the queue or SD card.
  if (subtype != 4 && subtype != 5 && subtype != 8 &&
      subtype != 10 && subtype != 12) return;

  MonitorFrame frame{};
  frame.timestampUs = micros();
  frame.originalLength = length;
  frame.capturedLength = length < MONITOR_SNAPLEN ? length : MONITOR_SNAPLEN;
  frame.rssi = packet->rx_ctrl.rssi;
  frame.channel = packet->rx_ctrl.channel;
  frame.subtype = subtype;
  frame.saveToPcap = subtype == 5 || subtype == 8;
  memcpy(frame.transmitter, payload + 10, 6);
  memcpy(frame.bssid, payload + 16, 6);
  if ((subtype == 10 || subtype == 12) && length >= 26) {
    frame.reasonCode = payload[24] | (static_cast<uint16_t>(payload[25]) << 8);
  }
  if (frame.saveToPcap) memcpy(frame.bytes, payload, frame.capturedLength);

  if (xQueueSend(monitorQueue, &frame, 0) != pdTRUE) monitorDropped++;
}

// ---------------------------- Logging ----------------------------

void addLog(const char* category, const char* format, ...) {
  LogEntry& entry = logBuffer[logHead];
  entry.timestamp = millis();
  strlcpy(entry.category, category, sizeof(entry.category));

  va_list args;
  va_start(args, format);
  vsnprintf(entry.message, sizeof(entry.message), format, args);
  va_end(args);

  Serial.printf("[%8lu] %-8s %s\n",
                static_cast<unsigned long>(entry.timestamp),
                entry.category,
                entry.message);

  logHead = (logHead + 1) % MAX_LOGS;
  if (logCount < MAX_LOGS) {
    logCount++;
  }

  if (sdReady) {
    char persistent[SD_LOG_LINE_LENGTH];
    char clockText[12];
    formatClock(clockText, sizeof(clockText));
    snprintf(persistent, sizeof(persistent), "[%s] [%lu] [%s] %s",
             clockText,
             static_cast<unsigned long>(entry.timestamp),
             entry.category,
             entry.message);
    enqueueSDLog(persistent);
    if (strcmp(entry.category, "SECURITY") == 0) appendSecurityAudit(entry.message);
  }
}

const LogEntry& logFromNewest(uint8_t offset) {
  int16_t index = static_cast<int16_t>(logHead) - 1 - offset;
  while (index < 0) index += MAX_LOGS;
  return logBuffer[index];
}

void enqueueSDLog(const char* line) {
  if (!sdReady || !line) return;

  if (sdLogQueueCount >= SD_LOG_QUEUE_LINES) {
    sdLogQueueTail = (sdLogQueueTail + 1) % SD_LOG_QUEUE_LINES;
    sdLogQueueCount--;
  }

  strlcpy(sdLogQueue[sdLogQueueHead], line, SD_LOG_LINE_LENGTH);
  sdLogQueueHead = (sdLogQueueHead + 1) % SD_LOG_QUEUE_LINES;
  sdLogQueueCount++;
}

void releaseSPIForSD() {
  digitalWrite(PIN_TFT_CS, HIGH);
  digitalWrite(PIN_TOUCH_CS, HIGH);
  digitalWrite(PIN_SD_CS, HIGH);
}

bool initializeSD() {
  pinMode(PIN_SD_CS, OUTPUT);
  releaseSPIForSD();

  if (!SD.begin(PIN_SD_CS, SPI, 4000000)) {
    SD.end();
    if (!SD.begin(PIN_SD_CS, SPI, 1000000)) return false;
  }

  if (SD.cardType() == CARD_NONE) return false;

  if (!SD.exists("/krnl")) SD.mkdir("/krnl");
  if (!SD.exists("/krnl/logs")) SD.mkdir("/krnl/logs");
  if (!SD.exists("/krnl/scans")) SD.mkdir("/krnl/scans");
  if (!SD.exists("/krnl/captures")) SD.mkdir("/krnl/captures");

  File summary = SD.open("/krnl/summaries.csv", FILE_APPEND);
  if (summary && summary.size() == 0) {
    summary.println("clock,session,scan,results,visible,open,warnings,duration_ms,free_heap");
  }
  if (summary) summary.close();

  File alerts = SD.open("/krnl/alerts.csv", FILE_APPEND);
  if (alerts && alerts.size() == 0) {
    alerts.println("clock,session,scan,score,ssid,bssid,channel,security,reason");
  }
  if (alerts) alerts.close();

  File security = SD.open("/krnl/security.csv", FILE_APPEND);
  if (security && security.size() == 0) {
    security.println("clock,uptime_ms,session,event");
  }
  if (security) security.close();

  File irEvents = SD.open("/krnl/ir.csv", FILE_APPEND);
  if (irEvents && irEvents.size() == 0) {
    irEvents.println("clock,uptime_ms,session,burst,edges,min_low_us,max_low_us,min_high_us,max_high_us");
  }
  if (irEvents) irEvents.close();

  File monitorEvents = SD.open("/krnl/monitor_events.csv", FILE_APPEND);
  if (monitorEvents && monitorEvents.size() == 0) {
    monitorEvents.println("clock,uptime_ms,session,event,channel,rssi,transmitter,bssid,reason");
  }
  if (monitorEvents) monitorEvents.close();

  sdSessionId = prefs.getUShort("session", 0) + 1;
  prefs.putUShort("session", sdSessionId);
  snprintf(sdLogPath, sizeof(sdLogPath), "/krnl/logs/S%04u.log", sdSessionId);
  snprintf(sdScanPath, sizeof(sdScanPath), "/krnl/scans/S%04u.csv", sdSessionId);

  File logFile = SD.open(sdLogPath, FILE_APPEND);
  if (!logFile) return false;
  logFile.printf("KRNL SESSION %04u\n", sdSessionId);
  logFile.println("Persistent event log; entries contain clock time and milliseconds since boot.");
  logFile.close();

  File csv = SD.open(sdScanPath, FILE_APPEND);
  if (!csv) return false;
  if (csv.size() == 0) {
    csv.println("clock,uptime_ms,scan,ssid,bssid,rssi,channel,security,status,sightings,channel_changes,security_changes,anomaly");
  }
  csv.close();

  loadBaseline();

  char manifestPath[48];
  snprintf(manifestPath, sizeof(manifestPath), "/krnl/logs/S%04u.meta", sdSessionId);
  File manifest = SD.open(manifestPath, FILE_WRITE);
  if (manifest) {
    manifest.printf("session=%u\n", sdSessionId);
    manifest.printf("reset_reason=%d\n", static_cast<int>(esp_reset_reason()));
    manifest.printf("cpu_mhz=%u\n", ESP.getCpuFreqMHz());
    manifest.printf("flash_bytes=%lu\n", static_cast<unsigned long>(ESP.getFlashChipSize()));
    manifest.printf("sd_total_bytes=%llu\n", static_cast<unsigned long long>(SD.totalBytes()));
    manifest.close();
  }

  releaseSPIForSD();
  lastSDFlushAt = millis();
  return true;
}

void flushSDLogs(bool force) {
  if (!sdReady || sdLogQueueCount == 0) return;
  if (!force && millis() - lastSDFlushAt < 2000) return;

  releaseSPIForSD();
  File file = SD.open(sdLogPath, FILE_APPEND);
  if (!file) {
    sdWriteError = true;
    return;
  }

  while (sdLogQueueCount > 0) {
    size_t written = file.println(sdLogQueue[sdLogQueueTail]);
    sdBytesWritten += written;
    sdLogQueueTail = (sdLogQueueTail + 1) % SD_LOG_QUEUE_LINES;
    sdLogQueueCount--;
  }

  file.close();
  digitalWrite(PIN_SD_CS, HIGH);
  sdWriteError = false;
  lastSDFlushAt = millis();
}

void writeCSVField(File& file, const char* value) {
  file.print('"');
  if (value) {
    while (*value) {
      if (*value == '"') file.print('"');
      file.print(*value++);
    }
  }
  file.print('"');
}

void appendIREvent() {
  if (!sdReady) return;
  releaseSPIForSD();
  File irEvents = SD.open("/krnl/ir.csv", FILE_APPEND);
  if (!irEvents) {
    sdWriteError = true;
    return;
  }

  char clockText[12];
  formatClock(clockText, sizeof(clockText));
  irEvents.printf("%s,%lu,%u,%lu,%lu,%lu,%lu,%lu,%lu\n",
                  clockText,
                  static_cast<unsigned long>(lastIRBurstAt),
                  sdSessionId,
                  static_cast<unsigned long>(irBurstCount),
                  static_cast<unsigned long>(lastIREdges),
                  static_cast<unsigned long>(lastIRMinLowUs),
                  static_cast<unsigned long>(lastIRMaxLowUs),
                  static_cast<unsigned long>(lastIRMinHighUs),
                  static_cast<unsigned long>(lastIRMaxHighUs));
  irEvents.close();
  digitalWrite(PIN_SD_CS, HIGH);
  sdWriteError = false;
}

void serviceIRReceiver() {
  noInterrupts();
  uint32_t pendingEdges = irEdgeCount;
  uint32_t finalEdgeAt = irLastEdgeAtUs;
  interrupts();

  if (pendingEdges == 0 || micros() - finalEdgeAt <= IR_BURST_END_US) return;

  noInterrupts();
  lastIREdges = irEdgeCount;
  lastIRMinLowUs = irShortestLowUs == UINT32_MAX ? 0 : irShortestLowUs;
  lastIRMaxLowUs = irLongestLowUs;
  lastIRMinHighUs = irShortestHighUs == UINT32_MAX ? 0 : irShortestHighUs;
  lastIRMaxHighUs = irLongestHighUs;
  irEdgeCount = 0;
  irLastEdgeAtUs = 0;
  irShortestLowUs = UINT32_MAX;
  irLongestLowUs = 0;
  irShortestHighUs = UINT32_MAX;
  irLongestHighUs = 0;
  interrupts();

  // Reject isolated electrical glitches but retain complete remote bursts.
  if (lastIREdges < 4) return;

  irBurstCount++;
  lastIRBurstAt = millis();
  addLog("IR", "Burst %lu: %lu edges",
         static_cast<unsigned long>(irBurstCount),
         static_cast<unsigned long>(lastIREdges));
  appendIREvent();

  if (currentScreen == TOOLS && toolsMode == 3) uiDirty = true;
}

void macToText(const uint8_t* mac, char* output, size_t size) {
  snprintf(output, size, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char* monitorSubtypeName(uint8_t subtype) {
  switch (subtype) {
    case 4: return "PROBE REQUEST";
    case 5: return "PROBE RESPONSE";
    case 8: return "BEACON";
    case 10: return "DISASSOCIATION";
    case 12: return "DEAUTHENTICATION";
    default: return "MANAGEMENT";
  }
}

void appendMonitorEvent(const MonitorFrame& frame, const char* eventName) {
  if (!sdReady) return;
  releaseSPIForSD();
  File events = SD.open("/krnl/monitor_events.csv", FILE_APPEND);
  if (!events) {
    sdWriteError = true;
    return;
  }

  char clockText[12];
  char transmitter[18];
  char bssid[18];
  formatClock(clockText, sizeof(clockText));
  macToText(frame.transmitter, transmitter, sizeof(transmitter));
  macToText(frame.bssid, bssid, sizeof(bssid));
  events.printf("%s,%lu,%u,%s,%u,%d,%s,%s,%u\n",
                clockText, static_cast<unsigned long>(millis()), sdSessionId,
                eventName, frame.channel, frame.rssi, transmitter, bssid,
                frame.reasonCode);
  events.close();
  digitalWrite(PIN_SD_CS, HIGH);
  sdWriteError = false;
}

bool startPacketMonitor() {
  if (monitorActive || !monitorQueue) return monitorActive;

  esp_wifi_scan_stop();
  WiFi.scanDelete();
  scanRunning = false;
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  delay(30);

  xQueueReset(monitorQueue);
  monitorFrames = monitorBeacons = 0;
  monitorProbeRequests = monitorProbeResponses = 0;
  monitorDeauth = monitorDisassoc = 0;
  monitorDropped = 0;
  monitorPacketsPerSecond = monitorPpsAccumulator = 0;
  monitorPpsWindowAt = millis();
  lastMonitorHopAt = millis();

  wifi_promiscuous_filter_t filter{};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  if (esp_wifi_set_promiscuous(false) != ESP_OK ||
      esp_wifi_set_promiscuous_filter(&filter) != ESP_OK ||
      esp_wifi_set_promiscuous_rx_cb(wifiMonitorCallback) != ESP_OK ||
      esp_wifi_set_channel(monitorChannel, WIFI_SECOND_CHAN_NONE) != ESP_OK) {
    addLog("ERROR", "Packet Monitor initialization failed");
    WiFi.setSleep(radioPowerSave);
    return false;
  }

  monitorActive = true;
  if (esp_wifi_set_promiscuous(true) != ESP_OK) {
    monitorActive = false;
    addLog("ERROR", "Unable to enable monitor mode");
    WiFi.setSleep(radioPowerSave);
    return false;
  }

  monitorCapturePath[0] = '\0';
  if (sdReady) {
    monitorCaptureId = prefs.getUShort("capture", 0) + 1;
    prefs.putUShort("capture", monitorCaptureId);
    snprintf(monitorCapturePath, sizeof(monitorCapturePath),
             "/krnl/captures/C%04u.pcap", monitorCaptureId);

    releaseSPIForSD();
    File capture = SD.open(monitorCapturePath, FILE_WRITE);
    if (capture) {
      const PcapGlobalHeader header = {
        0xA1B2C3D4, 2, 4, 0, 0, MONITOR_SNAPLEN, 105
      };
      capture.write(reinterpret_cast<const uint8_t*>(&header), sizeof(header));
      capture.close();
    } else {
      sdWriteError = true;
      monitorCapturePath[0] = '\0';
    }
    digitalWrite(PIN_SD_CS, HIGH);
  }

  addLog("MONITOR", "Started ch%u%s", monitorChannel,
         monitorChannelHop ? " hopping" : " fixed");
  if (monitorCapturePath[0]) addLog("MONITOR", "PCAP: %s", monitorCapturePath);
  flushSDLogs(true);
  k17Mood = K17_SCANNING;
  uiDirty = true;
  return true;
}

void stopPacketMonitor() {
  if (!monitorActive) return;
  monitorActive = false;
  esp_wifi_set_promiscuous(false);
  xQueueReset(monitorQueue);
  WiFi.setSleep(radioPowerSave);
  nextScanAt = millis() + 1000;
  addLog("MONITOR", "Stopped: %lu frames, %lu dropped",
         static_cast<unsigned long>(monitorFrames),
         static_cast<unsigned long>(monitorDropped));
  flushSDLogs(true);
  k17Mood = K17_DONE;
  uiDirty = true;
}

void servicePacketMonitor() {
  if (!monitorActive || !monitorQueue) return;

  uint32_t now = millis();
  if (monitorChannelHop && now - lastMonitorHopAt >= MONITOR_HOP_INTERVAL_MS) {
    lastMonitorHopAt = now;
    monitorChannel = monitorChannel >= 13 ? 1 : monitorChannel + 1;
    esp_wifi_set_channel(monitorChannel, WIFI_SECOND_CHAN_NONE);
  }

  File capture;
  bool captureOpen = false;
  MonitorFrame frame;
  uint8_t processed = 0;
  while (processed < MONITOR_QUEUE_LENGTH &&
         xQueueReceive(monitorQueue, &frame, 0) == pdTRUE) {
    processed++;
    monitorFrames++;
    monitorPpsAccumulator++;
    lastMonitorSubtype = frame.subtype;
    lastMonitorRSSI = frame.rssi;
    lastMonitorChannel = frame.channel;
    lastMonitorReason = frame.reasonCode;
    macToText(frame.transmitter, lastMonitorTransmitter,
              sizeof(lastMonitorTransmitter));
    macToText(frame.bssid, lastMonitorBSSID, sizeof(lastMonitorBSSID));

    switch (frame.subtype) {
      case 4: monitorProbeRequests++; break;
      case 5: monitorProbeResponses++; break;
      case 8: monitorBeacons++; break;
      case 10: monitorDisassoc++; break;
      case 12: monitorDeauth++; break;
    }

    if ((frame.subtype == 10 || frame.subtype == 12) &&
        now - lastDisruptionLogAt >= 500) {
      lastDisruptionLogAt = now;
      addLog("ALERT", "%s ch%u reason%u",
             monitorSubtypeName(frame.subtype), frame.channel, frame.reasonCode);
      appendMonitorEvent(frame, monitorSubtypeName(frame.subtype));
      k17Mood = K17_ERROR;
    }

    if (frame.saveToPcap && monitorCapturePath[0]) {
      if (!captureOpen) {
        releaseSPIForSD();
        capture = SD.open(monitorCapturePath, FILE_APPEND);
        captureOpen = static_cast<bool>(capture);
      }
      if (captureOpen) {
        PcapRecordHeader record = {
          frame.timestampUs / 1000000UL,
          frame.timestampUs % 1000000UL,
          frame.capturedLength,
          frame.originalLength
        };
        capture.write(reinterpret_cast<const uint8_t*>(&record), sizeof(record));
        capture.write(frame.bytes, frame.capturedLength);
      }
    }
  }

  if (captureOpen) {
    capture.close();
    digitalWrite(PIN_SD_CS, HIGH);
  }

  if (now - monitorPpsWindowAt >= 1000) {
    monitorPacketsPerSecond = monitorPpsAccumulator;
    monitorPpsAccumulator = 0;
    monitorPpsWindowAt = now;
  }

  if (currentScreen == TOOLS && toolsMode == 4 &&
      now - lastMonitorUIAt >= 500) {
    lastMonitorUIAt = now;
    uiDirty = true;
  }
}

void appendSecurityAudit(const char* event) {
  if (!sdReady || !event) return;
  releaseSPIForSD();
  File security = SD.open("/krnl/security.csv", FILE_APPEND);
  if (!security) {
    sdWriteError = true;
    return;
  }
  char clockText[12];
  formatClock(clockText, sizeof(clockText));
  security.printf("%s,%lu,%u,", clockText,
                  static_cast<unsigned long>(millis()), sdSessionId);
  writeCSVField(security, event);
  security.println();
  security.close();
  sdWriteError = false;
}

void appendScanCSV() {
  if (!sdReady) return;

  releaseSPIForSD();
  File csv = SD.open(sdScanPath, FILE_APPEND);
  if (!csv) {
    sdWriteError = true;
    return;
  }
  size_t bytesBefore = csv.size();

  char clockText[12];
  formatClock(clockText, sizeof(clockText));

  for (uint8_t i = 0; i < visibleAPCount; i++) {
    uint8_t index = sortedAP[i];
    const AccessPoint& ap = apCache[index];
    csv.print(clockText);
    csv.print(',');
    csv.print(millis());
    csv.print(',');
    csv.print(completedScans);
    csv.print(',');
    writeCSVField(csv, ap.ssid);
    csv.print(',');
    writeCSVField(csv, ap.bssid);
    csv.print(',');
    csv.print(ap.rssi);
    csv.print(',');
    csv.print(ap.channel);
    csv.print(',');
    csv.print(authName(ap.auth));
    csv.print(',');
    csv.print(ap.active ? "present" : "missing");
    csv.print(',');
    csv.print(ap.sightings);
    csv.print(',');
    csv.print(ap.channelChanges);
    csv.print(',');
    csv.print(ap.securityChanges);
    csv.print(',');
    csv.println(anomalyScore(index));
  }

  sdBytesWritten += csv.size() - bytesBefore;
  csv.close();
  digitalWrite(PIN_SD_CS, HIGH);
  sdWriteError = false;
}

void writeLatestSnapshot() {
  if (!sdReady) return;
  releaseSPIForSD();
  SD.remove("/krnl/latest.csv");
  File latest = SD.open("/krnl/latest.csv", FILE_WRITE);
  if (!latest) {
    sdWriteError = true;
    return;
  }
  latest.println("ssid,bssid,rssi,channel,security,anomaly");
  for (uint8_t i = 0; i < visibleAPCount; i++) {
    uint8_t index = sortedAP[i];
    const AccessPoint& ap = apCache[index];
    if (!ap.active) continue;
    writeCSVField(latest, ap.ssid);
    latest.print(',');
    writeCSVField(latest, ap.bssid);
    latest.printf(",%ld,%u,%s,%u\n", static_cast<long>(ap.rssi), ap.channel,
                  authName(ap.auth), anomalyScore(index));
  }
  latest.close();
  sdWriteError = false;
}

void appendScanSummary(int16_t resultCount) {
  if (!sdReady) return;
  releaseSPIForSD();
  File summary = SD.open("/krnl/summaries.csv", FILE_APPEND);
  if (!summary) {
    sdWriteError = true;
    return;
  }
  char clockText[12];
  formatClock(clockText, sizeof(clockText));
  summary.printf("%s,%u,%lu,%d,%u,%u,%u,%lu,%lu\n", clockText, sdSessionId,
                 static_cast<unsigned long>(completedScans), resultCount,
                 visibleAPCount, countOpenNetworks(), warningCount(),
                 static_cast<unsigned long>(lastScanDurationMs),
                 static_cast<unsigned long>(ESP.getFreeHeap()));
  summary.close();
  sdWriteError = false;
}

void appendAnomalyArchive() {
  if (!sdReady) return;
  releaseSPIForSD();
  File alerts = SD.open("/krnl/alerts.csv", FILE_APPEND);
  if (!alerts) {
    sdWriteError = true;
    return;
  }
  char clockText[12];
  formatClock(clockText, sizeof(clockText));
  for (uint8_t i = 0; i < visibleAPCount; i++) {
    uint8_t index = sortedAP[i];
    AccessPoint& ap = apCache[index];
    uint8_t score = anomalyScore(index);
    if (score < 35 || score == ap.lastAlertScore) continue;
    alerts.printf("%s,%u,%lu,%u,", clockText, sdSessionId,
                  static_cast<unsigned long>(completedScans), score);
    writeCSVField(alerts, ap.ssid);
    alerts.print(',');
    writeCSVField(alerts, ap.bssid);
    alerts.printf(",%u,%s,", ap.channel, authName(ap.auth));
    writeCSVField(alerts, hasSecurityMismatch(index) ? "SSID security mismatch" :
                          ap.securityChanges ? "security changed" :
                          ap.auth == 0 ? "open network" : "heuristic threshold");
    alerts.println();
    ap.lastAlertScore = score;
    addLog("ALERT", "%s anomaly score %u", ap.ssid, score);
  }
  alerts.close();
  sdWriteError = false;
}

void writeConfigBackup() {
  if (!sdReady) return;
  releaseSPIForSD();
  SD.remove("/krnl/config.txt");
  File config = SD.open("/krnl/config.txt", FILE_WRITE);
  if (!config) {
    sdWriteError = true;
    return;
  }
  config.printf("auto_scan=%u\n", autoScan);
  config.printf("show_hidden=%u\n", showHidden);
  config.printf("scan_interval_ms=%lu\n", static_cast<unsigned long>(scanIntervalMs));
  config.printf("radio_power_save=%u\n", radioPowerSave);
  config.printf("adaptive_scan=%u\n", adaptiveScan);
  config.printf("guard_mode=%u\n", guardMode);
  config.printf("watchlist_count=%u\n", watchlistCount);
  config.printf("touch_calibrated=%u\n", calibrationValid);
  config.printf("access_pin_configured=%u\n", accessPinConfigured);
  config.println("access_pin_value=NEVER_EXPORTED");
  config.close();
  sdWriteError = false;
}

// ---------------------------- Helpers ----------------------------

const char* authName(uint8_t auth) {
  // Values follow wifi_auth_mode_t. Numeric cases keep this sketch
  // compatible across Arduino-ESP32 releases with different enum names.
  switch (auth) {
    case 0: return "OPEN";
    case 1: return "WEP";
    case 2: return "WPA";
    case 3: return "WPA2";
    case 4: return "WPA/WPA2";
    case 5: return "WPA2-ENT";
    case 6: return "WPA3";
    case 7: return "WPA2/WPA3";
    case 8: return "WAPI";
    case 9: return "OWE";
    default: return "SECURED";
  }
}

uint16_t rssiColor(int32_t rssi) {
  if (rssi >= -55) return C_GREEN;
  if (rssi >= -70) return C_YELLOW;
  if (rssi >= -82) return C_ORANGE;
  return C_RED;
}

uint8_t signalBars(int32_t rssi) {
  if (rssi >= -55) return 4;
  if (rssi >= -67) return 3;
  if (rssi >= -78) return 2;
  return 1;
}

void printClipped(const char* text, uint8_t maxCharacters) {
  char output[40];
  if (strlen(text) <= maxCharacters) {
    tft.print(text);
    return;
  }

  uint8_t copyLength = maxCharacters - 2;
  if (copyLength > sizeof(output) - 3) copyLength = sizeof(output) - 3;
  memcpy(output, text, copyLength);
  output[copyLength] = '.';
  output[copyLength + 1] = '.';
  output[copyLength + 2] = '\0';
  tft.print(output);
}

void formatUptime(uint32_t milliseconds, char* output, size_t size) {
  uint32_t totalSeconds = milliseconds / 1000;
  uint32_t hours = totalSeconds / 3600;
  uint32_t minutes = (totalSeconds % 3600) / 60;
  uint32_t seconds = totalSeconds % 60;
  snprintf(output, size, "%02lu:%02lu:%02lu",
           static_cast<unsigned long>(hours),
           static_cast<unsigned long>(minutes),
           static_cast<unsigned long>(seconds));
}

uint32_t currentClockSeconds() {
  uint32_t elapsed = (millis() - clockSetAtMillis) / 1000UL;
  return (clockBaseSeconds + elapsed) % 86400UL;
}

void formatClock(char* output, size_t size) {
  if (!clockConfigured) {
    strlcpy(output, "--:--:--", size);
    return;
  }

  uint32_t total = currentClockSeconds();
  uint8_t hour = total / 3600UL;
  uint8_t minute = (total % 3600UL) / 60UL;
  uint8_t second = total % 60UL;
  snprintf(output, size, "%02u:%02u:%02u", hour, minute, second);
}

void setManualClock(uint8_t hour, uint8_t minute) {
  clockBaseSeconds = static_cast<uint32_t>(hour) * 3600UL +
                     static_cast<uint32_t>(minute) * 60UL;
  clockSetAtMillis = millis();
  clockConfigured = true;

  prefs.putBool("clockSet", true);
  prefs.putUChar("clockHour", hour);
  prefs.putUChar("clockMin", minute);
}

void formatAge(uint32_t timestamp, char* output, size_t size) {
  uint32_t age = (millis() - timestamp) / 1000UL;
  if (age < 60) snprintf(output, size, "%lus ago", static_cast<unsigned long>(age));
  else if (age < 3600) snprintf(output, size, "%lum ago", static_cast<unsigned long>(age / 60));
  else snprintf(output, size, "%luh ago", static_cast<unsigned long>(age / 3600));
}

// -------------------------- AP database --------------------------

int16_t findAP(const char* bssid) {
  for (uint8_t i = 0; i < apCount; i++) {
    if (strcmp(apCache[i].bssid, bssid) == 0) return i;
  }
  return -1;
}

uint8_t cacheSlotForNewAP() {
  if (apCount < MAX_APS) return apCount++;

  uint8_t oldest = 0;
  for (uint8_t i = 1; i < MAX_APS; i++) {
    if (static_cast<int32_t>(apCache[i].lastSeen - apCache[oldest].lastSeen) < 0) {
      oldest = i;
    }
  }
  return oldest;
}

void rebuildSortedAPList() {
  visibleAPCount = 0;
  uint32_t now = millis();

  for (uint8_t i = 0; i < apCount; i++) {
    if (apCache[i].active || (now - apCache[i].lastSeen < 120000UL)) {
      sortedAP[visibleAPCount++] = i;
    }
  }

  for (uint8_t i = 0; i < visibleAPCount; i++) {
    for (uint8_t j = i + 1; j < visibleAPCount; j++) {
      if (apCache[sortedAP[j]].rssi > apCache[sortedAP[i]].rssi) {
        uint8_t temporary = sortedAP[i];
        sortedAP[i] = sortedAP[j];
        sortedAP[j] = temporary;
      }
    }
  }

  uint8_t pageCount = (visibleAPCount + RECON_ROWS - 1) / RECON_ROWS;
  if (pageCount == 0) pageCount = 1;
  if (reconPage >= pageCount) reconPage = pageCount - 1;
}

uint8_t countOpenNetworks() {
  uint8_t count = 0;
  for (uint8_t i = 0; i < visibleAPCount; i++) {
    if (apCache[sortedAP[i]].auth == 0) count++;
  }
  return count;
}

bool hasSecurityMismatch(uint8_t cacheIndex) {
  const AccessPoint& target = apCache[cacheIndex];
  if (target.hidden) return false;

  for (uint8_t i = 0; i < apCount; i++) {
    if (i == cacheIndex) continue;
    if (strcmp(target.ssid, apCache[i].ssid) == 0 &&
        strcmp(target.bssid, apCache[i].bssid) != 0 &&
        target.auth != apCache[i].auth) {
      return true;
    }
  }
  return false;
}

uint8_t duplicateSSIDCount(uint8_t cacheIndex) {
  const AccessPoint& target = apCache[cacheIndex];
  if (target.hidden) return 0;
  uint8_t count = 0;
  for (uint8_t i = 0; i < apCount; i++) {
    if (i != cacheIndex && strcmp(target.ssid, apCache[i].ssid) == 0) count++;
  }
  return count;
}

uint8_t channelCongestion(uint8_t channel) {
  uint16_t score = 0;
  for (uint8_t i = 0; i < visibleAPCount; i++) {
    const AccessPoint& ap = apCache[sortedAP[i]];
    int8_t distance = abs(static_cast<int8_t>(ap.channel) - static_cast<int8_t>(channel));
    if (distance <= 2) {
      uint8_t strength = constrain(map(ap.rssi, -95, -35, 2, 15), 2, 15);
      score += strength * (3 - distance);
    }
  }
  return score > 100 ? 100 : score;
}

uint8_t anomalyScore(uint8_t cacheIndex) {
  const AccessPoint& ap = apCache[cacheIndex];
  uint16_t score = 0;
  if (ap.auth == 0) score += 35;
  if (hasSecurityMismatch(cacheIndex)) score += 30;
  if (ap.securityChanges > 0) {
    uint16_t securityScore = ap.securityChanges * 10;
    score += securityScore > 20 ? 20 : securityScore;
  }
  if (ap.channelChanges > 1) {
    uint16_t channelScore = ap.channelChanges * 2;
    score += channelScore > 10 ? 10 : channelScore;
  }
  if (duplicateSSIDCount(cacheIndex) >= 3) score += 10;
  if (!ap.active) score += 5;
  return score > 100 ? 100 : score;
}

uint8_t warningCount() {
  uint8_t count = 0;
  for (uint8_t i = 0; i < visibleAPCount; i++) {
    if (anomalyScore(sortedAP[i]) >= 35) count++;
  }
  return count;
}

bool isWatchedBSSID(const char* bssid) {
  if (!bssid) return false;
  for (uint8_t i = 0; i < watchlistCount; i++) {
    if (strcmp(watchedBSSIDs[i], bssid) == 0) return true;
  }
  return false;
}

bool isInBaseline(const char* bssid) {
  if (!bssid) return false;
  for (uint8_t i = 0; i < baselineCount; i++) {
    if (strcmp(baselineBSSIDs[i], bssid) == 0) return true;
  }
  return false;
}

void loadBaseline() {
  baselineCount = 0;
  baselineReady = false;
  File baseline = SD.open("/krnl/baseline.csv", FILE_READ);
  if (!baseline) return;
  baseline.readStringUntil('\n');
  while (baseline.available() && baselineCount < MAX_APS) {
    String line = baseline.readStringUntil('\n');
    line.trim();
    int comma = line.indexOf(',');
    String bssid = comma >= 0 ? line.substring(0, comma) : line;
    if (bssid.length() == 17) {
      strlcpy(baselineBSSIDs[baselineCount++], bssid.c_str(), sizeof(baselineBSSIDs[0]));
    }
  }
  baseline.close();
  baselineReady = baselineCount > 0;
  baselineLearningScans = baselineReady ? 3 : 0;
}

void saveBaseline() {
  if (!sdReady) return;
  releaseSPIForSD();
  SD.remove("/krnl/baseline.csv");
  File baseline = SD.open("/krnl/baseline.csv", FILE_WRITE);
  if (!baseline) return;
  baseline.println("bssid,ssid,security,channel");
  baselineCount = 0;
  for (uint8_t i = 0; i < visibleAPCount && baselineCount < MAX_APS; i++) {
    const AccessPoint& ap = apCache[sortedAP[i]];
    if (!ap.active) continue;
    baseline.print(ap.bssid);
    baseline.print(',');
    writeCSVField(baseline, ap.ssid);
    baseline.printf(",%s,%u\n", authName(ap.auth), ap.channel);
    strlcpy(baselineBSSIDs[baselineCount++], ap.bssid, sizeof(baselineBSSIDs[0]));
  }
  baseline.close();
  baselineReady = baselineCount > 0;
  baselineLearningScans = baselineReady ? 3 : 0;
  addLog("GUARD", "Baseline saved: %u APs", baselineCount);
}

void resetBaseline() {
  if (sdReady) SD.remove("/krnl/baseline.csv");
  memset(baselineBSSIDs, 0, sizeof(baselineBSSIDs));
  baselineCount = 0;
  baselineReady = false;
  baselineLearningScans = 0;
  addLog("GUARD", "Baseline reset; learning restarted");
}

void saveWatchlist() {
  for (uint8_t i = 0; i < MAX_WATCHLIST; i++) {
    char key[9];
    snprintf(key, sizeof(key), "watch%u", i);
    prefs.putString(key, i < watchlistCount ? watchedBSSIDs[i] : "");
  }
}

void toggleWatchlist(const char* bssid) {
  for (uint8_t i = 0; i < watchlistCount; i++) {
    if (strcmp(watchedBSSIDs[i], bssid) == 0) {
      for (uint8_t j = i; j + 1 < watchlistCount; j++) {
        strlcpy(watchedBSSIDs[j], watchedBSSIDs[j + 1], sizeof(watchedBSSIDs[j]));
      }
      watchlistCount--;
      saveWatchlist();
      addLog("GUARD", "Removed watch: %s", bssid);
      return;
    }
  }
  if (watchlistCount >= MAX_WATCHLIST) {
    addLog("GUARD", "Watchlist full");
    return;
  }
  strlcpy(watchedBSSIDs[watchlistCount++], bssid, sizeof(watchedBSSIDs[0]));
  saveWatchlist();
  addLog("GUARD", "Watching: %s", bssid);
}

void simulateGuardIncident() {
  static const char* scenarios[] = {
    "SIMULATED SECURITY DOWNGRADE",
    "SIMULATED WATCHED AP LOSS",
    "SIMULATED ROGUE SSID MATCH"
  };
  const char* scenario = scenarios[simulatedIncidentCount % 3];
  simulatedIncidentCount++;
  k17Mood = K17_ERROR;
  addLog("SIM", "%s", scenario);

  if (sdReady) {
    releaseSPIForSD();
    File alerts = SD.open("/krnl/alerts.csv", FILE_APPEND);
    if (alerts) {
      char clockText[12];
      formatClock(clockText, sizeof(clockText));
      alerts.printf("%s,%u,%lu,90,", clockText, sdSessionId,
                    static_cast<unsigned long>(completedScans));
      writeCSVField(alerts, "<simulation>");
      alerts.print(',');
      writeCSVField(alerts, "00:00:00:00:00:00");
      alerts.print(",0,N/A,");
      writeCSVField(alerts, scenario);
      alerts.println();
      alerts.close();
    }
  }
  flushSDLogs(true);
}

// -------------------------- Wi-Fi scan ---------------------------

void startScan() {
  if (scanRunning || monitorActive) return;

  WiFi.scanDelete();
  k17Mood = K17_SCANNING;
  scanStartedAt = millis();
  addLog("RECON", "Starting passive Wi-Fi scan");

  int16_t state = WiFi.scanNetworks(true, showHidden);
  if (state == WIFI_SCAN_RUNNING) {
    scanRunning = true;
  } else if (state >= 0) {
    finishScan(state);
  } else {
    k17Mood = K17_ERROR;
    scanFailureCount++;
    addLog("ERROR", "Unable to start Wi-Fi scan");
    nextScanAt = millis() + scanIntervalMs;
  }
}

void finishScan(int16_t resultCount) {
  uint32_t now = millis();
  scanEventCount = 0;
  bool guardAlertTriggered = false;

  for (uint8_t i = 0; i < apCount; i++) {
    if (apCache[i].active && apCache[i].missedScans < 255) apCache[i].missedScans++;
    apCache[i].active = false;
  }

  for (int16_t result = 0; result < resultCount; result++) {
    String bssidString = WiFi.BSSIDstr(result);
    String ssidString = WiFi.SSID(result);
    bool hidden = ssidString.length() == 0;

    int16_t index = findAP(bssidString.c_str());
    bool isNew = index < 0;
    if (isNew) index = cacheSlotForNewAP();

    AccessPoint& ap = apCache[index];
    if (isNew) {
      memset(&ap, 0, sizeof(ap));
      ap.firstSeen = now;
      ap.sightings = 0;
    } else {
      uint8_t newChannel = WiFi.channel(result);
      uint8_t newAuth = static_cast<uint8_t>(WiFi.encryptionType(result));
      if (ap.channel != newChannel) {
        scanEventCount++;
        ap.channelChanges++;
        ap.lastChange = now;
        addLog("AP", "%s channel %u>%u", ap.ssid, ap.channel, newChannel);
      }
      if (ap.auth != newAuth) {
        scanEventCount++;
        ap.securityChanges++;
        ap.lastChange = now;
        addLog("WARN", "%s security changed", ap.ssid);
      }
    }

    strlcpy(ap.ssid, hidden ? "<hidden>" : ssidString.c_str(), sizeof(ap.ssid));
    strlcpy(ap.bssid, bssidString.c_str(), sizeof(ap.bssid));
    ap.rssi = WiFi.RSSI(result);
    ap.channel = WiFi.channel(result);
    ap.auth = static_cast<uint8_t>(WiFi.encryptionType(result));
    ap.hidden = hidden;
    ap.active = true;
    ap.missedScans = 0;
    ap.lastSeen = now;
    ap.sightings++;
    ap.rssiHistory[ap.historyHead] = constrain(ap.rssi, -127, 0);
    ap.historyHead = (ap.historyHead + 1) % RSSI_HISTORY_SAMPLES;
    if (ap.historyCount < RSSI_HISTORY_SAMPLES) ap.historyCount++;

    if (isNew) {
      scanEventCount++;
      addLog("AP", "New: %s ch%u %lddBm",
             ap.ssid,
             ap.channel,
             static_cast<long>(ap.rssi));
      if (guardMode && baselineReady && !isInBaseline(ap.bssid)) {
        addLog("ALERT", "Post-baseline AP: %s", ap.ssid);
        guardAlertTriggered = true;
      }
    }
  }

  completedScans++;
  if (!baselineReady && baselineLearningScans < 3) baselineLearningScans++;
  lastScanDurationMs = now - scanStartedAt;
  scanRunning = false;
  k17Mood = resultCount < 0 ? K17_ERROR : K17_DONE;
  if (guardAlertTriggered) k17Mood = K17_ERROR;
  if (scanEventCount > 0) stableScanCount = 0;
  else if (stableScanCount < 10) stableScanCount++;

  uint32_t effectiveInterval = scanIntervalMs;
  if (adaptiveScan) {
    if (scanEventCount > 0) effectiveInterval = 5000;
    else if (stableScanCount >= 5) effectiveInterval = max(scanIntervalMs, 30000UL);
  }
  nextScanAt = now + effectiveInterval;
  rebuildSortedAPList();
  if (!baselineReady && baselineLearningScans >= 3) saveBaseline();

  if (guardMode) {
    for (uint8_t i = 0; i < apCount; i++) {
      AccessPoint& ap = apCache[i];
      if (!ap.active && ap.missedScans == 1 && isWatchedBSSID(ap.bssid)) {
        addLog("ALERT", "Watched AP missing: %s", ap.ssid);
        k17Mood = K17_ERROR;
      }
    }
  }
  addLog("RECON", "Scan %lu complete: %d results",
         static_cast<unsigned long>(completedScans), resultCount);

  appendScanCSV();
  writeLatestSnapshot();
  appendScanSummary(resultCount);
  if (guardMode) appendAnomalyArchive();
  flushSDLogs(true);

  WiFi.scanDelete();
  uiDirty = true;
}

void serviceScanner() {
  if (monitorActive) return;
  if (scanRunning) {
    int16_t result = WiFi.scanComplete();
    if (result >= 0) {
      finishScan(result);
    } else if (result == WIFI_SCAN_FAILED) {
      scanRunning = false;
      k17Mood = K17_ERROR;
      scanFailureCount++;
      nextScanAt = millis() + scanIntervalMs;
      addLog("ERROR", "Wi-Fi scan failed");
    }
    return;
  }

  if (autoScan && static_cast<int32_t>(millis() - nextScanAt) >= 0) {
    startScan();
  }
}

// ----------------------------- Touch -----------------------------

void saveCalibration() {
  prefs.putInt("calX0", calibration.x0);
  prefs.putInt("calX1", calibration.x1);
  prefs.putInt("calY0", calibration.y0);
  prefs.putInt("calY1", calibration.y1);
  prefs.putBool("calSwap", calibration.swapXY);
  prefs.putUChar("calVer", 3);
  calibrationValid = true;
  writeConfigBackup();
}

void loadSettings() {
  prefs.begin("krnl", false);
  autoScan = prefs.getBool("autoScan", true);
  showHidden = prefs.getBool("hidden", true);
  radioPowerSave = prefs.getBool("powerSave", false);
  adaptiveScan = prefs.getBool("adaptive", true);
  guardMode = prefs.getBool("guard", true);
  scanIntervalMs = prefs.getULong("interval", 10000);
  calibration.x0 = prefs.getInt("calX0", 200);
  calibration.x1 = prefs.getInt("calX1", 3900);
  calibration.y0 = prefs.getInt("calY0", 200);
  calibration.y1 = prefs.getInt("calY1", 3900);
  calibration.swapXY = prefs.getBool("calSwap", false);
  calibrationValid = prefs.getUChar("calVer", 0) == 3;

  clockConfigured = prefs.getBool("clockSet", false);
  uint8_t savedHour = prefs.getUChar("clockHour", 12);
  uint8_t savedMinute = prefs.getUChar("clockMin", 0);
  clockBaseSeconds = static_cast<uint32_t>(savedHour) * 3600UL +
                     static_cast<uint32_t>(savedMinute) * 60UL;
  clockSetAtMillis = millis();

  accessPinConfigured = prefs.getBool("pinSet", false);
  accessPinHash = prefs.getUInt("pinHash", 0);

  watchlistCount = 0;
  for (uint8_t i = 0; i < MAX_WATCHLIST; i++) {
    char key[9];
    snprintf(key, sizeof(key), "watch%u", i);
    String watched = prefs.getString(key, "");
    if (watched.length() == 17) {
      strlcpy(watchedBSSIDs[watchlistCount++], watched.c_str(), sizeof(watchedBSSIDs[0]));
    }
  }
}

bool readTouch(int16_t& x, int16_t& y) {
  if (!touch.touched()) return false;

  TS_Point point = touch.getPoint();
  int32_t rawX = calibration.swapXY ? point.y : point.x;
  int32_t rawY = calibration.swapXY ? point.x : point.y;

  if (calibration.x0 == calibration.x1 || calibration.y0 == calibration.y1) {
    return false;
  }

  x = constrain(map(rawX, calibration.x0, calibration.x1, 0, SCREEN_W - 1), 0, SCREEN_W - 1);
  y = constrain(map(rawY, calibration.y0, calibration.y1, 0, SCREEN_H - 1), 0, SCREEN_H - 1);
  return true;
}

TS_Point captureCalibrationPoint(int16_t targetX, int16_t targetY, uint8_t number) {
  while (true) {
    tft.fillScreen(C_BG);
    tft.setTextColor(C_CYAN);
    tft.setTextSize(2);
    tft.setCursor(60, 100);
    tft.printf("CALIBRATION %u/4", number);
    tft.setTextSize(1);
    tft.setTextColor(C_GREY);
    tft.setCursor(83, 125);
    tft.print("PRESS, HOLD, THEN RELEASE");

    tft.drawCircle(targetX, targetY, 10, C_WHITE);
    tft.drawFastHLine(targetX - 14, targetY, 29, C_RED);
    tft.drawFastVLine(targetX, targetY - 14, 29, C_RED);

    while (touch.touched()) delay(8);
    while (!touch.touched()) delay(8);

    int32_t totalX = 0;
    int32_t totalY = 0;
    int32_t totalZ = 0;
    uint8_t samples = 0;

    while (touch.touched() && samples < 32) {
      TS_Point point = touch.getPoint();
      if (point.z > 80) {
        totalX += point.x;
        totalY += point.y;
        totalZ += point.z;
        samples++;
      }
      delay(8);
    }

    if (samples >= 4) {
      return TS_Point(totalX / samples, totalY / samples, totalZ / samples);
    }

    tft.fillRect(75, 150, 170, 25, C_BG);
    tft.setTextColor(C_RED);
    tft.setTextSize(1);
    tft.setCursor(105, 158);
    tft.print("TAP TOO SHORT - RETRY");
    delay(700);
  }
}

void runCalibration() {
  addLog("UI", "Touch calibration started");

  bool valid = false;
  while (!valid) {
    TS_Point points[4];
    points[0] = captureCalibrationPoint(20, 20, 1);
    points[1] = captureCalibrationPoint(299, 20, 2);
    points[2] = captureCalibrationPoint(299, 219, 3);
    points[3] = captureCalibrationPoint(20, 219, 4);

    int32_t horizontalX = abs(((points[1].x + points[2].x) / 2) -
                              ((points[0].x + points[3].x) / 2));
    int32_t horizontalY = abs(((points[1].y + points[2].y) / 2) -
                              ((points[0].y + points[3].y) / 2));

    calibration.swapXY = horizontalY > horizontalX;

    auto axisX = [&](const TS_Point& point) {
      return calibration.swapXY ? point.y : point.x;
    };
    auto axisY = [&](const TS_Point& point) {
      return calibration.swapXY ? point.x : point.y;
    };

    int32_t left = (axisX(points[0]) + axisX(points[3])) / 2;
    int32_t right = (axisX(points[1]) + axisX(points[2])) / 2;
    int32_t top = (axisY(points[0]) + axisY(points[1])) / 2;
    int32_t bottom = (axisY(points[2]) + axisY(points[3])) / 2;

    int32_t xSpan = right - left;
    int32_t ySpan = bottom - top;
    valid = abs(xSpan) > 500 && abs(ySpan) > 500;

    if (valid) {
      // Targets are inset by 20 px. Extrapolate the raw endpoints so the
      // captured targets map back to their actual on-screen coordinates.
      calibration.x0 = left - (xSpan * 20L) / 279L;
      calibration.x1 = right + (xSpan * 20L) / 279L;
      calibration.y0 = top - (ySpan * 20L) / 199L;
      calibration.y1 = bottom + (ySpan * 20L) / 199L;
    } else {
      tft.fillScreen(C_BG);
      tft.setTextColor(C_RED);
      tft.setTextSize(2);
      tft.setCursor(65, 100);
      tft.print("CALIBRATION FAILED");
      tft.setTextSize(1);
      tft.setCursor(72, 130);
      tft.print("REPEATING FOUR-POINT TEST");
      delay(1000);
    }
  }

  saveCalibration();
  addLog("UI", "Calibration saved");

  tft.fillScreen(C_BG);
  tft.setTextColor(C_GREEN);
  tft.setTextSize(2);
  tft.setCursor(58, 105);
  tft.print("CALIBRATION SAVED");
  delay(1000);

  touchLatched = true;
  fullRedraw = true;
  uiDirty = true;
}

void drawTimeEditor(uint8_t hour, uint8_t minute) {
  tft.fillScreen(C_BG);
  tft.drawRect(4, 4, 312, 232, C_CYAN);

  tft.setTextColor(C_CYAN);
  tft.setTextSize(2);
  tft.setCursor(103, 18);
  tft.print("SET TIME");

  tft.setTextColor(C_GREY);
  tft.setTextSize(1);
  tft.setCursor(74, 44);
  tft.print("Time advances while KRNL is powered");

  tft.fillRect(90, 60, 140, 42, C_PANEL);
  tft.drawRect(90, 60, 140, 42, C_DARKCYAN);
  tft.setTextColor(C_GREEN);
  tft.setTextSize(3);
  tft.setCursor(106, 69);
  tft.printf("%02u:%02u", hour, minute);

  const int16_t buttonY = 116;
  tft.setTextSize(2);

  tft.drawRoundRect(18, buttonY, 55, 35, 4, C_CYAN);
  tft.setCursor(35, buttonY + 10);
  tft.print("H-");

  tft.drawRoundRect(82, buttonY, 55, 35, 4, C_CYAN);
  tft.setCursor(99, buttonY + 10);
  tft.print("H+");

  tft.drawRoundRect(183, buttonY, 55, 35, 4, C_CYAN);
  tft.setCursor(198, buttonY + 10);
  tft.print("M-");

  tft.drawRoundRect(247, buttonY, 55, 35, 4, C_CYAN);
  tft.setCursor(262, buttonY + 10);
  tft.print("M+");

  tft.fillRoundRect(45, 174, 100, 38, 4, C_DARKCYAN);
  tft.drawRoundRect(45, 174, 100, 38, 4, C_GREEN);
  tft.setTextColor(C_WHITE);
  tft.setCursor(69, 186);
  tft.print("SAVE");

  tft.drawRoundRect(175, 174, 100, 38, 4, C_GREY);
  tft.setCursor(190, 186);
  tft.print("CANCEL");
}

void runTimeEditor() {
  uint8_t hour = 12;
  uint8_t minute = 0;

  if (clockConfigured) {
    uint32_t now = currentClockSeconds();
    hour = now / 3600UL;
    minute = (now % 3600UL) / 60UL;
  }

  drawTimeEditor(hour, minute);
  while (touch.touched()) delay(10);

  bool finished = false;
  bool save = false;

  while (!finished) {
    int16_t x;
    int16_t y;
    if (!readTouch(x, y)) {
      delay(10);
      continue;
    }

    if (y >= 110 && y <= 158) {
      if (x >= 10 && x <= 76) {
        hour = (hour + 23) % 24;
      } else if (x >= 77 && x <= 145) {
        hour = (hour + 1) % 24;
      } else if (x >= 175 && x <= 242) {
        minute = (minute + 59) % 60;
      } else if (x >= 243 && x <= 310) {
        minute = (minute + 1) % 60;
      }
      drawTimeEditor(hour, minute);
    } else if (y >= 168 && y <= 218) {
      if (x >= 35 && x <= 155) {
        save = true;
        finished = true;
      } else if (x >= 165 && x <= 285) {
        finished = true;
      }
    }

    while (touch.touched()) delay(10);
    delay(80);
  }

  if (save) {
    setManualClock(hour, minute);
    addLog("SYSTEM", "Clock set to %02u:%02u", hour, minute);
  }

  touchLatched = true;
  fullRedraw = true;
  uiDirty = true;
}

uint32_t hashAccessPin(const char pin[5]) {
  // Device-salted local hash. This deters casual access but is not a secure
  // element and can still be bypassed by reflashing the development board.
  uint32_t hash = 2166136261UL;
  uint64_t chipId = ESP.getEfuseMac();
  for (uint8_t i = 0; i < 8; i++) {
    hash ^= static_cast<uint8_t>(chipId >> (i * 8));
    hash *= 16777619UL;
  }
  for (uint8_t i = 0; i < 4; i++) {
    hash ^= static_cast<uint8_t>(pin[i]);
    hash *= 16777619UL;
  }
  return hash;
}

void drawPinPad(const char* title, uint8_t entered) {
  tft.fillScreen(C_BG);
  tft.drawRect(4, 4, 312, 232, C_CYAN);
  tft.setTextColor(C_CYAN);
  tft.setTextSize(2);
  tft.setCursor(52, 15);
  tft.print(title);

  tft.setTextSize(2);
  tft.setTextColor(C_GREEN);
  tft.setCursor(125, 44);
  for (uint8_t i = 0; i < 4; i++) tft.print(i < entered ? '*' : '_');

  const char* keys[12] = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "CLR", "0", "OK"};
  for (uint8_t key = 0; key < 12; key++) {
    uint8_t row = key / 3;
    uint8_t column = key % 3;
    int16_t x = 42 + column * 82;
    int16_t y = 70 + row * 39;
    tft.drawRoundRect(x, y, 72, 32, 4,
                      key == 11 ? C_GREEN : key == 9 ? C_ORANGE : C_DARKCYAN);
    tft.setTextColor(C_WHITE);
    tft.setTextSize(key == 9 ? 1 : 2);
    tft.setCursor(x + (key == 9 ? 25 : 30), y + (key == 9 ? 12 : 9));
    tft.print(keys[key]);
  }
}

void readPinEntry(const char* title, char output[5]) {
  uint8_t entered = 0;
  memset(output, 0, 5);
  drawPinPad(title, entered);
  while (touch.touched()) delay(8);

  while (true) {
    int16_t x;
    int16_t y;
    if (!readTouch(x, y)) {
      delay(8);
      continue;
    }

    if (x >= 36 && x <= 286 && y >= 65 && y <= 229) {
      int8_t column = (x - 42) / 82;
      int8_t row = (y - 70) / 39;
      if (column >= 0 && column < 3 && row >= 0 && row < 4) {
        uint8_t key = row * 3 + column;
        if (key <= 8 && entered < 4) {
          output[entered++] = '1' + key;
        } else if (key == 9) {
          entered = 0;
          memset(output, 0, 5);
        } else if (key == 10 && entered < 4) {
          output[entered++] = '0';
        } else if (key == 11 && entered == 4) {
          while (touch.touched()) delay(8);
          return;
        }
        drawPinPad(title, entered);
      }
    }

    while (touch.touched()) delay(8);
    delay(60);
  }
}

bool verifyAccessPin(const char* title) {
  char entered[5];
  readPinEntry(title, entered);
  bool valid = hashAccessPin(entered) == accessPinHash;

  if (!valid) {
    addLog("SECURITY", "Incorrect access PIN entered");
    flushSDLogs(true);
    tft.fillScreen(C_BG);
    tft.setTextColor(C_RED);
    tft.setTextSize(2);
    tft.setCursor(93, 105);
    tft.print("ACCESS DENIED");
    delay(900);
  } else {
    addLog("SECURITY", "Access PIN accepted");
  }
  return valid;
}

void configureOrUnlock() {
  if (!accessPinConfigured || accessPinHash == 0) {
    while (true) {
      char first[5];
      char confirmation[5];
      readPinEntry("CREATE 4-DIGIT PIN", first);
      readPinEntry("CONFIRM ACCESS PIN", confirmation);
      if (strcmp(first, confirmation) == 0) {
        accessPinHash = hashAccessPin(first);
        accessPinConfigured = true;
        prefs.putUInt("pinHash", accessPinHash);
        prefs.putBool("pinSet", true);
        addLog("SECURITY", "Access PIN created");
        break;
      }

      tft.fillScreen(C_BG);
      tft.setTextColor(C_RED);
      tft.setTextSize(2);
      tft.setCursor(75, 105);
      tft.print("PIN DOES NOT MATCH");
      delay(1000);
    }
  } else {
    uint8_t failures = 0;
    while (!verifyAccessPin("KRNL ACCESS LOCK")) {
      failures++;
      if (failures >= 5) {
        addLog("SECURITY", "Temporary lockout after 5 failures");
        flushSDLogs(true);
        for (int8_t seconds = 10; seconds > 0; seconds--) {
          tft.fillScreen(C_BG);
          tft.setTextColor(C_ORANGE);
          tft.setTextSize(2);
          tft.setCursor(68, 95);
          tft.print("TEMPORARY LOCKOUT");
          tft.setCursor(145, 125);
          tft.print(seconds);
          delay(1000);
        }
        failures = 0;
      }
    }
  }

  tft.fillScreen(C_BG);
  tft.setTextColor(C_GREEN);
  tft.setTextSize(2);
  tft.setCursor(80, 105);
  tft.print("ACCESS GRANTED");
  delay(500);
  touchLatched = true;
  fullRedraw = true;
  uiDirty = true;
}

bool confirmKRNLWipe() {
  tft.fillScreen(C_BG);
  tft.drawRect(4, 4, 312, 232, C_RED);
  tft.setTextColor(C_RED);
  tft.setTextSize(2);
  tft.setCursor(62, 24);
  tft.print("WIPE KRNL DATA?");
  tft.setTextSize(1);
  tft.setTextColor(C_WHITE);
  tft.setCursor(42, 70);
  tft.print("Deletes every KRNL-created SD record");
  tft.setCursor(42, 88);
  tft.print("Other SD files and settings are preserved.");
  tft.setTextColor(C_GREEN);
  tft.drawRoundRect(20, 165, 125, 42, 5, C_GREEN);
  tft.setCursor(64, 182);
  tft.print("CANCEL");
  tft.setTextColor(C_RED);
  tft.drawRoundRect(175, 165, 125, 42, 5, C_RED);
  tft.setCursor(222, 182);
  tft.print("WIPE");

  while (touch.touched()) delay(8);
  while (true) {
    int16_t x;
    int16_t y;
    if (readTouch(x, y) && y >= 158 && y <= 214) {
      while (touch.touched()) delay(8);
      if (x >= 15 && x <= 150) return false;
      if (x >= 170 && x <= 305) return true;
    }
    delay(8);
  }
}

void removeKRNLFiles(const char* directoryPath) {
  File directory = SD.open(directoryPath);
  if (!directory || !directory.isDirectory()) {
    if (directory) directory.close();
    return;
  }

  File entry = directory.openNextFile();
  while (entry) {
    String entryName = entry.name();
    bool isDirectory = entry.isDirectory();
    entry.close();

    String fullPath = entryName.startsWith("/")
                        ? entryName
                        : String(directoryPath) + "/" + entryName;
    if (!isDirectory) SD.remove(fullPath.c_str());
    entry = directory.openNextFile();
  }
  directory.close();
}

void wipeKRNLData() {
  if (monitorActive) stopPacketMonitor();
  addLog("SECURITY", "KRNL data wipe authorized");
  flushSDLogs(true);
  WiFi.scanDelete();
  scanRunning = false;
  if (sdReady) {
    releaseSPIForSD();
    removeKRNLFiles("/krnl/logs");
    removeKRNLFiles("/krnl/scans");
    removeKRNLFiles("/krnl/captures");
    SD.remove("/krnl/latest.csv");
    SD.remove("/krnl/summaries.csv");
    SD.remove("/krnl/alerts.csv");
    SD.remove("/krnl/security.csv");
    SD.remove("/krnl/ir.csv");
    SD.remove("/krnl/monitor_events.csv");
    SD.remove("/krnl/baseline.csv");
    SD.remove("/krnl/config.txt");
    SD.rmdir("/krnl/logs");
    SD.rmdir("/krnl/scans");
    SD.rmdir("/krnl/captures");
    SD.end();
  }

  sdReady = false;
  sdWriteError = false;
  sdLogQueueHead = sdLogQueueTail = sdLogQueueCount = 0;
  sdBytesWritten = 0;
  memset(apCache, 0, sizeof(apCache));
  memset(logBuffer, 0, sizeof(logBuffer));
  apCount = visibleAPCount = logCount = logHead = 0;
  selectedAP = -1;
  reconPage = 0;
  completedScans = 0;
  baselineReady = false;
  baselineCount = 0;
  baselineLearningScans = 0;
  scanFailureCount = 0;
  irBurstCount = 0;
  lastIRBurstAt = 0;
  lastIREdges = 0;
  lastIRMinLowUs = lastIRMaxLowUs = 0;
  lastIRMinHighUs = lastIRMaxHighUs = 0;
  monitorFrames = monitorBeacons = 0;
  monitorProbeRequests = monitorProbeResponses = 0;
  monitorDeauth = monitorDisassoc = 0;
  monitorDropped = 0;
  monitorCapturePath[0] = '\0';
  nextScanAt = millis() + scanIntervalMs;

  sdReady = initializeSD();
  writeConfigBackup();
  addLog("SECURITY", "KRNL data wipe completed");
  addLog("SYSTEM", sdReady ? "New SD session: %s" : "SD unavailable after wipe",
         sdReady ? sdLogPath : "");
  flushSDLogs(true);

  tft.fillScreen(C_BG);
  tft.setTextColor(sdReady ? C_GREEN : C_ORANGE);
  tft.setTextSize(2);
  tft.setCursor(72, 105);
  tft.print(sdReady ? "KRNL DATA WIPED" : "WIPE COMPLETE");
  delay(900);
  fullRedraw = true;
  uiDirty = true;
}

// ---------------------------- Drawing ----------------------------

const char* k17MoodName() {
  switch (k17Mood) {
    case K17_SCANNING: return "SCANNING";
    case K17_DONE: return "COMPLETE";
    case K17_ERROR: return "ALERT";
    case K17_INSPECT: return "INSPECT";
    default: return "NOMINAL";
  }
}

void drawK17Avatar() {
  constexpr int16_t x = 290;
  constexpr int16_t y = 2;
  tft.fillRect(x, y, 27, 20, C_PANEL);
  tft.drawRect(x, y, 27, 20, k17Mood == K17_ERROR ? C_RED : C_CYAN);

  bool blink = (k17Frame % 24) == 0;
  int8_t look = k17Mood == K17_INSPECT ? ((k17Frame / 3) % 3) - 1 : 0;

  if (k17Mood == K17_ERROR) {
    tft.drawLine(x + 7, y + 6, x + 11, y + 10, C_RED);
    tft.drawLine(x + 11, y + 6, x + 7, y + 10, C_RED);
    tft.drawLine(x + 16, y + 6, x + 20, y + 10, C_RED);
    tft.drawLine(x + 20, y + 6, x + 16, y + 10, C_RED);
    tft.drawFastHLine(x + 8, y + 15, 11, C_RED);
  } else {
    uint16_t eye = k17Mood == K17_SCANNING ? C_YELLOW : C_GREEN;
    if (blink) {
      tft.drawFastHLine(x + 7, y + 8, 5, eye);
      tft.drawFastHLine(x + 16, y + 8, 5, eye);
    } else {
      tft.fillRect(x + 8 + look, y + 7, 2, 2, eye);
      tft.fillRect(x + 17 + look, y + 7, 2, 2, eye);
    }

    if (k17Mood == K17_DONE) {
      tft.drawLine(x + 8, y + 14, x + 11, y + 16, C_GREEN);
      tft.drawFastHLine(x + 11, y + 16, 6, C_GREEN);
      tft.drawLine(x + 17, y + 16, x + 20, y + 14, C_GREEN);
    } else {
      tft.drawFastHLine(x + 9, y + 15, 10, eye);
    }

    if (k17Mood == K17_SCANNING) {
      int16_t sweepX = x + 3 + (k17Frame % 21);
      tft.drawFastVLine(sweepX, y + 3, 14, C_CYAN);
    }
  }
}

void serviceK17Animation() {
  if (millis() - lastK17Update < 120) return;
  lastK17Update = millis();
  k17Frame++;
  drawK17Avatar();
}

void drawHeader() {
  tft.fillRect(0, 0, SCREEN_W, HEADER_H, C_PANEL);
  tft.drawFastHLine(0, HEADER_H - 1, SCREEN_W, C_DARKCYAN);

  tft.setTextSize(1);
  tft.setTextColor(C_CYAN);
  tft.setCursor(5, 5);
  tft.print("KRNL // ");

  tft.setTextColor(scanRunning ? C_YELLOW : C_GREEN);
  tft.print(scanRunning ? "SCANNING" : "ONLINE");

  char clockText[12];
  formatClock(clockText, sizeof(clockText));
  tft.setTextColor(C_GREY);
  tft.setCursor(205, 5);
  tft.print(clockText);

  drawK17Avatar();
}

void drawNavigation() {
  static const char* labels[6] = {"HOME", "RECON", "DETAIL", "LOGS", "TOOLS", "SET"};

  tft.fillRect(0, NAV_Y, SCREEN_W, SCREEN_H - NAV_Y, C_PANEL);
  tft.drawFastHLine(0, NAV_Y, SCREEN_W, C_DARKCYAN);

  for (uint8_t i = 0; i < 6; i++) {
    int16_t x = i * 53;
    if (currentScreen == i) {
      tft.fillRect(x + 1, NAV_Y + 2, 51, 24, C_DARKCYAN);
    }
    tft.setTextSize(1);
    tft.setTextColor(currentScreen == i ? C_WHITE : C_GREY);
    tft.setCursor(x + 5, NAV_Y + 10);
    tft.print(labels[i]);
  }
}

void drawTitle(const char* title, const char* subtitle = nullptr) {
  tft.setTextSize(2);
  tft.setTextColor(C_CYAN);
  tft.setCursor(10, 31);
  tft.print(title);

  if (subtitle) {
    tft.setTextSize(1);
    tft.setTextColor(C_GREY);
    tft.setCursor(10, 50);
    tft.print(subtitle);
  }
}

void drawHome() {
  drawTitle("SYSTEM HOME", "Passive wireless environment monitor");

  tft.drawRect(10, 67, 94, 55, C_GRID);
  tft.drawRect(113, 67, 94, 55, C_GRID);
  tft.drawRect(216, 67, 94, 55, C_GRID);

  tft.setTextSize(3);
  tft.setTextColor(C_GREEN);
  tft.setCursor(22, 78);
  tft.print(visibleAPCount);

  tft.setTextColor(C_RED);
  tft.setCursor(126, 78);
  tft.print(countOpenNetworks());

  tft.setTextColor(C_CYAN);
  tft.setCursor(229, 78);
  tft.print(completedScans);

  tft.setTextSize(1);
  tft.setTextColor(C_GREY);
  tft.setCursor(22, 108);
  tft.print("AP CACHE");
  tft.setCursor(126, 108);
  tft.print("OPEN");
  tft.setCursor(229, 108);
  tft.print("SCANS");

  tft.setTextColor(warningCount() ? C_YELLOW : C_GREEN);
  tft.setCursor(105, 130);
  tft.printf("ANOMALY FLAGS: %u", warningCount());

  tft.fillRoundRect(35, 142, 250, 45, 4, C_DARKCYAN);
  tft.drawRoundRect(35, 142, 250, 45, 4, C_CYAN);
  tft.setTextSize(2);
  tft.setTextColor(C_WHITE);
  tft.setCursor(83, 157);
  tft.print(scanRunning ? "SCAN IN PROGRESS" : "OPEN RECON MODULE");

  tft.setTextSize(1);
  tft.setTextColor(C_GREEN);
  tft.setCursor(95, 199);
  tft.printf("KRNL-17: %s", k17MoodName());
}

void drawSignalIcon(int16_t x, int16_t y, int32_t rssi) {
  uint8_t bars = signalBars(rssi);
  uint16_t color = rssiColor(rssi);
  for (uint8_t i = 0; i < 4; i++) {
    uint8_t height = 3 + i * 3;
    tft.fillRect(x + i * 4, y + 12 - height, 3, height,
                 i < bars ? color : C_GRID);
  }
}

void drawRecon() {
  rebuildSortedAPList();
  uint8_t pages = (visibleAPCount + RECON_ROWS - 1) / RECON_ROWS;
  if (pages == 0) pages = 1;

  drawTitle("RECON", scanRunning ? "Scanning 2.4 GHz..." : "Tap an access point for details");

  tft.setTextSize(1);
  tft.setTextColor(C_GREY);
  tft.setCursor(245, 34);
  tft.printf("%u/%u", reconPage + 1, pages);
  tft.drawRect(282, 29, 28, 22, C_DARKCYAN);
  tft.setCursor(292, 36);
  tft.print(">");

  uint8_t start = reconPage * RECON_ROWS;
  for (uint8_t row = 0; row < RECON_ROWS; row++) {
    uint8_t listIndex = start + row;
    int16_t y = 58 + row * 29;
    tft.drawFastHLine(8, y + 26, 304, C_GRID);

    if (listIndex >= visibleAPCount) continue;
    const AccessPoint& ap = apCache[sortedAP[listIndex]];

    drawSignalIcon(12, y + 5, ap.rssi);
    tft.setTextSize(1);
    tft.setTextColor(C_WHITE);
    tft.setCursor(34, y + 4);
    printClipped(ap.ssid, 22);

    tft.setTextColor(C_GREY);
    tft.setCursor(34, y + 16);
    tft.printf("CH%02u  %lddBm", ap.channel, static_cast<long>(ap.rssi));

    tft.setTextColor(ap.auth == 0 ? C_RED : C_GREEN);
    tft.setCursor(241, y + 10);
    tft.print(authName(ap.auth));
    if (isWatchedBSSID(ap.bssid)) {
      tft.setTextColor(C_YELLOW);
      tft.setCursor(226, y + 10);
      tft.print("W");
    }
  }
}

void drawDetails() {
  drawTitle(detailsPage == 0 ? "AP DETAILS" : "LIVE SIGNAL",
            detailsPage == 0 ? "Cached beacon metadata" : "History, guard and simulation");

  tft.drawRect(270, 29, 40, 22, C_DARKCYAN);
  tft.setTextColor(C_CYAN);
  tft.setCursor(280, 36);
  tft.print(detailsPage == 0 ? "LIVE" : "INFO");

  if (selectedAP < 0 || selectedAP >= apCount) {
    tft.setTextSize(2);
    tft.setTextColor(C_GREY);
    tft.setCursor(45, 105);
    tft.print("SELECT AP IN RECON");
    return;
  }

  const AccessPoint& ap = apCache[selectedAP];

  if (detailsPage == 1) {
    constexpr int16_t graphX = 20;
    constexpr int16_t graphY = 65;
    constexpr int16_t graphW = 280;
    constexpr int16_t graphH = 82;
    tft.drawRect(graphX, graphY, graphW, graphH, C_DARKCYAN);
    for (uint8_t line = 1; line < 4; line++) {
      tft.drawFastHLine(graphX + 1, graphY + line * graphH / 4,
                        graphW - 2, C_GRID);
    }
    tft.setTextSize(1);
    tft.setTextColor(C_GREY);
    tft.setCursor(3, graphY + 2);
    tft.print("-30");
    tft.setCursor(3, graphY + graphH - 8);
    tft.print("-100");

    if (ap.historyCount > 0) {
      uint8_t oldest = (ap.historyHead + RSSI_HISTORY_SAMPLES - ap.historyCount) % RSSI_HISTORY_SAMPLES;
      int16_t previousX = graphX + 4;
      int16_t previousY = graphY + graphH - 4;
      for (uint8_t i = 0; i < ap.historyCount; i++) {
        int8_t sample = ap.rssiHistory[(oldest + i) % RSSI_HISTORY_SAMPLES];
        int16_t x = graphX + 4 + (ap.historyCount == 1 ? 0 : i * (graphW - 8) / (ap.historyCount - 1));
        int16_t y = map(constrain(sample, -100, -30), -100, -30,
                        graphY + graphH - 4, graphY + 4);
        if (i > 0) tft.drawLine(previousX, previousY, x, y, rssiColor(sample));
        tft.fillCircle(x, y, 2, rssiColor(sample));
        previousX = x;
        previousY = y;
      }
    }

    bool watched = isWatchedBSSID(ap.bssid);
    tft.drawRoundRect(20, 162, 130, 34, 4, watched ? C_GREEN : C_CYAN);
    tft.setTextColor(watched ? C_GREEN : C_CYAN);
    tft.setCursor(watched ? 51 : 43, 175);
    tft.print(watched ? "WATCHING" : "ADD WATCH");
    tft.drawRoundRect(170, 162, 130, 34, 4, C_ORANGE);
    tft.setTextColor(C_ORANGE);
    tft.setCursor(195, 175);
    tft.print("SIM INCIDENT");
    return;
  }

  const int16_t labelX = 15;
  const int16_t valueX = 88;
  int16_t y = 61;

  auto field = [&](const char* label, const char* value, uint16_t color = C_WHITE) {
    tft.setTextSize(1);
    tft.setTextColor(C_GREY);
    tft.setCursor(labelX, y);
    tft.print(label);
    tft.setTextColor(color);
    tft.setCursor(valueX, y);
    printClipped(value, 35);
    y += 14;
  };

  char number[32];
  field("SSID", ap.ssid, C_CYAN);
  field("BSSID", ap.bssid);
  snprintf(number, sizeof(number), "%ld dBm", static_cast<long>(ap.rssi));
  field("SIGNAL", number, rssiColor(ap.rssi));
  snprintf(number, sizeof(number), "%u / 2.4 GHz", ap.channel);
  field("CHANNEL", number);
  field("SECURITY", authName(ap.auth), ap.auth == 0 ? C_RED : C_GREEN);
  snprintf(number, sizeof(number), "%u", ap.sightings);
  field("SIGHTINGS", number);
  field("STATUS", ap.active ? "PRESENT" : "NOT IN LAST SCAN",
        ap.active ? C_GREEN : C_ORANGE);
  formatAge(ap.firstSeen, number, sizeof(number));
  field("FIRST SEEN", number);
  formatAge(ap.lastSeen, number, sizeof(number));
  field("LAST SEEN", number);
  snprintf(number, sizeof(number), "CH:%u SEC:%u DUP:%u",
           ap.channelChanges, ap.securityChanges, duplicateSSIDCount(selectedAP));
  field("CHANGES", number, (ap.securityChanges || ap.channelChanges) ? C_YELLOW : C_GREEN);
  snprintf(number, sizeof(number), "%u/100  CONGEST:%u%s",
           anomalyScore(selectedAP), channelCongestion(ap.channel),
           isWatchedBSSID(ap.bssid) ? " WATCH" : "");
  field("ANOMALY", number, anomalyScore(selectedAP) >= 35 ? C_RED : C_GREEN);
}

void drawLogs() {
  drawTitle("SYSTEM LOGS", "Newest events first");

  tft.setTextSize(1);
  tft.setTextColor(sdWriteError ? C_RED : sdReady ? C_GREEN : C_ORANGE);
  tft.setCursor(177, 36);
  if (sdReady) tft.printf("SD:S%04u Q:%u", sdSessionId, sdLogQueueCount);
  else tft.print("SD:OFFLINE");

  tft.drawRect(265, 29, 45, 22, C_DARKCYAN);
  tft.setTextSize(1);
  tft.setTextColor(C_GREY);
  tft.setCursor(274, 36);
  tft.print("CLEAR");

  uint8_t rows = logCount < 8 ? logCount : 8;
  for (uint8_t i = 0; i < rows; i++) {
    const LogEntry& entry = logFromNewest(i);
    int16_t y = 61 + i * 18;

    tft.setTextSize(1);
    tft.setTextColor(C_DARKCYAN);
    tft.setCursor(8, y);
    tft.printf("%05lu", static_cast<unsigned long>(entry.timestamp / 1000));

    tft.setTextColor(C_YELLOW);
    tft.setCursor(44, y);
    tft.printf("%-6s", entry.category);

    tft.setTextColor(C_WHITE);
    tft.setCursor(86, y);
    printClipped(entry.message, 37);
  }

  tft.drawRect(6, 190, 308, 18, C_DARKCYAN);
}

void serviceLogsWaveform() {
  if (currentScreen != LOGS || uiDirty) return;
  if (millis() - lastLogsWaveUpdate < 120) return;
  lastLogsWaveUpdate = millis();

  constexpr int16_t x = 8;
  constexpr int16_t y = 192;
  constexpr int16_t w = 304;
  constexpr int16_t h = 14;
  int16_t baseline = y + h / 2;

  tft.fillRect(x, y, w, h, C_BG);
  tft.drawFastHLine(x, baseline, w, C_GRID);
  float phase = millis() * 0.006f;
  for (int16_t px = 0; px < w; px += 6) {
    float wave = sinf(phase + px * 0.17f) + 0.45f * sinf(phase * 1.7f + px * 0.41f);
    int16_t amplitude = constrain(static_cast<int16_t>(fabsf(wave) * 4), 1, 6);
    tft.drawFastVLine(x + px, baseline - amplitude, amplitude * 2 + 1, C_GREEN);
  }
}

void drawChannelAnalysis() {
  uint8_t occupancy[14] = {0};

  for (uint8_t i = 0; i < visibleAPCount; i++) {
    const AccessPoint& ap = apCache[sortedAP[i]];
    if (ap.channel >= 1 && ap.channel <= 13) {
      occupancy[ap.channel]++;
    }
  }

  int16_t baseline = 180;
  for (uint8_t channel = 1; channel <= 13; channel++) {
    int16_t x = 13 + (channel - 1) * 23;
    int16_t height = occupancy[channel] == 0 ? 2 : 10 + occupancy[channel] * 12;
    if (height > 100) height = 100;
    uint16_t color = occupancy[channel] >= 4 ? C_RED :
                     occupancy[channel] >= 2 ? C_YELLOW : C_GREEN;

    tft.fillRect(x, baseline - height, 15, height, color);
    tft.setTextSize(1);
    tft.setTextColor(C_GREY);
    tft.setCursor(x + (channel < 10 ? 5 : 1), baseline + 5);
    tft.print(channel);
  }

  tft.drawFastHLine(10, baseline, 300, C_GRID);
  tft.setTextColor(C_GREY);
  tft.setCursor(12, 202);
  tft.printf("OPEN:%u  CACHE:%u  HEAP:%luKB",
             countOpenNetworks(), visibleAPCount,
             static_cast<unsigned long>(ESP.getFreeHeap() / 1024));
}

uint32_t radarHash(const char* text) {
  uint32_t hash = 2166136261UL;
  while (*text) {
    hash ^= static_cast<uint8_t>(*text++);
    hash *= 16777619UL;
  }
  return hash;
}

void drawRadarElements() {
  constexpr int16_t cx = 160;
  constexpr int16_t cy = 125;
  constexpr int16_t radius = 68;

  tft.drawCircle(cx, cy, radius, C_DARKCYAN);
  tft.drawCircle(cx, cy, 45, C_GRID);
  tft.drawCircle(cx, cy, 22, C_GRID);
  tft.drawFastHLine(cx - radius, cy, radius * 2 + 1, C_GRID);
  tft.drawFastVLine(cx, cy - radius, radius * 2 + 1, C_GRID);

  uint8_t blips = visibleAPCount < 24 ? visibleAPCount : 24;
  for (uint8_t i = 0; i < blips; i++) {
    const AccessPoint& ap = apCache[sortedAP[i]];
    uint32_t hash = radarHash(ap.bssid);
    float angle = (hash % 360) * DEG_TO_RAD;
    int16_t distance = constrain(map(ap.rssi, -35, -95, 10, radius - 5), 10, radius - 5);
    int16_t x = cx + static_cast<int16_t>(cosf(angle) * distance);
    int16_t y = cy + static_cast<int16_t>(sinf(angle) * distance);
    uint16_t color = ap.auth == 0 ? C_RED : rssiColor(ap.rssi);
    tft.fillCircle(x, y, 2, color);
  }

  tft.fillCircle(cx, cy, 3, C_CYAN);
}

int16_t radarBlipAt(int16_t tapX, int16_t tapY) {
  constexpr int16_t cx = 160;
  constexpr int16_t cy = 125;
  constexpr int16_t radius = 68;
  constexpr int16_t hitRadius = 10;

  int16_t nearest = -1;
  int32_t nearestDistanceSquared = hitRadius * hitRadius + 1;
  uint8_t blips = visibleAPCount < 24 ? visibleAPCount : 24;

  for (uint8_t i = 0; i < blips; i++) {
    const AccessPoint& ap = apCache[sortedAP[i]];
    uint32_t hash = radarHash(ap.bssid);
    float angle = (hash % 360) * DEG_TO_RAD;
    int16_t distance = constrain(map(ap.rssi, -35, -95, 10, radius - 5), 10, radius - 5);
    int16_t blipX = cx + static_cast<int16_t>(cosf(angle) * distance);
    int16_t blipY = cy + static_cast<int16_t>(sinf(angle) * distance);
    int32_t dx = tapX - blipX;
    int32_t dy = tapY - blipY;
    int32_t distanceSquared = dx * dx + dy * dy;

    if (distanceSquared < nearestDistanceSquared) {
      nearestDistanceSquared = distanceSquared;
      nearest = sortedAP[i];
    }
  }

  return nearest;
}

void drawRadarView() {
  drawRadarElements();

  constexpr int16_t cx = 160;
  constexpr int16_t cy = 125;
  constexpr int16_t radius = 68;
  int16_t endX = cx + static_cast<int16_t>(cosf(radarSweepAngle) * radius);
  int16_t endY = cy + static_cast<int16_t>(sinf(radarSweepAngle) * radius);
  tft.drawLine(cx, cy, endX, endY, C_GREEN);

  tft.setTextSize(1);
  tft.setTextColor(C_GREY);
  tft.setCursor(12, 199);
  tft.printf("BLIPS:%u  RED=OPEN  RANGE=RSSI", visibleAPCount);
}

void runBLEScan() {
  if (scanRunning) return;

#if KRNL_ENABLE_BLE
  k17Mood = K17_SCANNING;
  tft.fillRect(10, 58, 300, 130, C_BG);
  tft.setTextColor(C_YELLOW);
  tft.setTextSize(2);
  tft.setCursor(65, 105);
  tft.print("BLE SCANNING 4s");

  if (!bleInitialized) {
    BLEDevice::init("KRNL");
    bleInitialized = true;
  }

  BLEScan* scanner = BLEDevice::getScan();
  scanner->setActiveScan(false);
  scanner->setInterval(100);
  scanner->setWindow(80);

  BLEScanResults* results = scanner->start(4, false);
  bleDeviceCount = 0;

  if (results) {
    int count = results->getCount();
    int stored = count < 10 ? count : 10;
    for (int i = 0; i < stored; i++) {
      BLEAdvertisedDevice device = results->getDevice(i);
      String name = device.haveName() ? String(device.getName().c_str()) : String("<unnamed>");
      String address = String(device.getAddress().toString().c_str());
      strlcpy(bleRecords[i].name, name.c_str(), sizeof(bleRecords[i].name));
      strlcpy(bleRecords[i].address, address.c_str(), sizeof(bleRecords[i].address));
      bleRecords[i].rssi = device.getRSSI();
    }
    bleDeviceCount = stored;
  }

  scanner->clearResults();
  k17Mood = K17_DONE;
  addLog("BLE", "Passive scan found %u devices", bleDeviceCount);
  uiDirty = true;
#else
  bleDeviceCount = 0;
  k17Mood = K17_ERROR;
  addLog("BLE", "Disabled: enable Huge APP build profile");
  tft.fillRect(10, 58, 300, 130, C_BG);
  tft.setTextColor(C_ORANGE);
  tft.setTextSize(2);
  tft.setCursor(50, 93);
  tft.print("BLE BUILD DISABLED");
  tft.setTextSize(1);
  tft.setTextColor(C_WHITE);
  tft.setCursor(33, 125);
  tft.print("Set KRNL_ENABLE_BLE=1 and select");
  tft.setCursor(47, 142);
  tft.print("Partition Scheme: Huge APP");
  delay(1400);
  uiDirty = true;
#endif
}

void drawDiagnostics() {
  int16_t y = 60;
  auto line = [&](const char* label, const String& value, uint16_t color = C_WHITE) {
    tft.setTextSize(1);
    tft.setTextColor(C_GREY);
    tft.setCursor(12, y);
    tft.print(label);
    tft.setTextColor(color);
    tft.setCursor(125, y);
    tft.print(value);
    y += 15;
  };

  line("CPU", String(ESP.getCpuFreqMHz()) + " MHz", C_GREEN);
  line("FREE HEAP", String(ESP.getFreeHeap() / 1024) + " KB");
  line("MIN HEAP", String(ESP.getMinFreeHeap() / 1024) + " KB");
  line("SCAN STATS", String(lastScanDurationMs) + "ms / " + String(scanFailureCount) + " fail");
  line("WIFI RADIO", scanRunning ? "SCANNING" : "READY", scanRunning ? C_YELLOW : C_GREEN);
  line("TOUCH IRQ", digitalRead(PIN_TOUCH_IRQ) ? "IDLE" : "ACTIVE", C_GREEN);
  line("AP CACHE", String(visibleAPCount) + "/" + String(MAX_APS));
  line("BLE DEVICES", KRNL_ENABLE_BLE ? String(bleDeviceCount) : String("BUILD DISABLED"),
       KRNL_ENABLE_BLE ? C_WHITE : C_ORANGE);
  line("POWER SAVE", radioPowerSave ? "ON" : "OFF", radioPowerSave ? C_GREEN : C_GREY);
  String sdStatus = "NOT FOUND";
  if (sdReady) {
    uint32_t usedMB = static_cast<uint32_t>(SD.usedBytes() / (1024ULL * 1024ULL));
    uint32_t totalMB = static_cast<uint32_t>(SD.totalBytes() / (1024ULL * 1024ULL));
    sdStatus = sdWriteError ? "WRITE ERROR" : String(usedMB) + "/" + String(totalMB) + " MB";
  }
  line("SD USED/TOTAL", sdStatus, sdReady && !sdWriteError ? C_GREEN : C_ORANGE);

  if (bleDeviceCount > 0) {
    tft.setTextColor(C_CYAN);
    tft.setCursor(205, 60);
    printClipped(bleRecords[0].name, 16);
    tft.setCursor(205, 75);
    tft.printf("%ddBm", bleRecords[0].rssi);
  }
}

void drawIRMonitor() {
  bool idleHigh = digitalRead(PIN_IR_RECEIVER);

  tft.setTextSize(1);
  tft.setTextColor(C_GREY);
  tft.setCursor(14, 62);
  tft.print("TSOP1838B INPUT");
  tft.setTextColor(idleHigh ? C_GREEN : C_RED);
  tft.setCursor(125, 62);
  tft.print(idleHigh ? "HIGH / READY" : "LOW / CHECK WIRING");

  tft.drawRoundRect(12, 78, 296, 63, 5,
                    lastIRBurstAt ? C_GREEN : C_DARKCYAN);
  tft.setTextSize(2);
  tft.setTextColor(lastIRBurstAt ? C_GREEN : C_YELLOW);
  tft.setCursor(lastIRBurstAt ? 46 : 72, 90);
  tft.print(lastIRBurstAt ? "IR BURST DETECTED" : "WAITING FOR IR");

  tft.setTextSize(1);
  tft.setTextColor(C_WHITE);
  tft.setCursor(25, 120);
  tft.printf("BURSTS:%lu  LAST EDGES:%lu",
             static_cast<unsigned long>(irBurstCount),
             static_cast<unsigned long>(lastIREdges));

  tft.drawRect(12, 150, 220, 55, C_DARKCYAN);
  tft.setTextColor(C_GREY);
  tft.setCursor(22, 160);
  tft.print("LAST DEMODULATED TIMINGS");
  tft.setTextColor(C_CYAN);
  tft.setCursor(22, 177);
  tft.printf("LOW  %lu - %lu us", static_cast<unsigned long>(lastIRMinLowUs),
             static_cast<unsigned long>(lastIRMaxLowUs));
  tft.setCursor(22, 192);
  tft.printf("HIGH %lu - %lu us", static_cast<unsigned long>(lastIRMinHighUs),
             static_cast<unsigned long>(lastIRMaxHighUs));

  // Activity glyph: the receiver remains active even while other screens run.
  tft.drawCircle(270, 169, 18, lastIRBurstAt ? C_GREEN : C_GRID);
  tft.drawCircle(270, 169, 10, lastIRBurstAt ? C_CYAN : C_GRID);
  tft.fillCircle(270, 169, 3, idleHigh ? C_GREEN : C_RED);
  tft.setTextColor(C_GREY);
  tft.setCursor(250, 195);
  tft.print("RX ONLY");
}

void drawPacketMonitor() {
  tft.setTextSize(1);
  tft.setTextColor(C_GREY);
  tft.setCursor(13, 60);
  tft.print("PASSIVE MANAGEMENT-FRAME MONITOR");

  tft.drawRoundRect(12, 74, 296, 63, 5, monitorActive ? C_GREEN : C_DARKCYAN);
  tft.setTextSize(2);
  tft.setTextColor(monitorActive ? C_GREEN : C_YELLOW);
  tft.setCursor(24, 85);
  tft.print(monitorActive ? "CAPTURE ACTIVE" : "CAPTURE STOPPED");
  tft.setTextSize(1);
  tft.setTextColor(C_WHITE);
  tft.setCursor(23, 112);
  tft.printf("CH:%02u %s  PPS:%lu  DROP:%lu", monitorChannel,
             monitorChannelHop ? "HOP" : "FIX",
             static_cast<unsigned long>(monitorPacketsPerSecond),
             static_cast<unsigned long>(monitorDropped));

  tft.drawRect(12, 145, 54, 29, C_DARKCYAN);
  tft.drawRect(72, 145, 100, 29, monitorChannelHop ? C_GREEN : C_DARKCYAN);
  tft.drawRect(178, 145, 54, 29, C_DARKCYAN);
  tft.setTextColor(C_CYAN);
  tft.setCursor(30, 156);
  tft.print("CH-");
  tft.setCursor(101, 156);
  tft.print(monitorChannelHop ? "HOP" : "FIXED");
  tft.setCursor(196, 156);
  tft.print("CH+");

  tft.setTextColor(C_WHITE);
  tft.setCursor(14, 181);
  tft.printf("B:%lu PRQ:%lu PRS:%lu", static_cast<unsigned long>(monitorBeacons),
             static_cast<unsigned long>(monitorProbeRequests),
             static_cast<unsigned long>(monitorProbeResponses));
  tft.setCursor(14, 195);
  tft.setTextColor((monitorDeauth + monitorDisassoc) ? C_ORANGE : C_GREY);
  tft.printf("DEAUTH:%lu DISASSOC:%lu", static_cast<unsigned long>(monitorDeauth),
             static_cast<unsigned long>(monitorDisassoc));

  tft.setTextColor(C_GREY);
  tft.setCursor(239, 151);
  tft.print("PCAP:");
  tft.setCursor(239, 164);
  tft.print(sdReady ? "SD READY" : "NO SD");
}

void drawTools() {
  const char* titles[5] = {"TACTICAL RADAR", "CHANNEL ANALYSIS", "DIAGNOSTICS", "IR MONITOR", "PACKET MONITOR"};
  const char* subtitles[5] = {
    "Relative visualization based on RSSI",
    "Access points per 2.4 GHz channel",
    "Hardware, memory and radio status",
    "Live 38 kHz remote-control activity",
    "Receive-only 802.11 management metadata"
  };
  drawTitle(titles[toolsMode], subtitles[toolsMode]);

  tft.drawRect(235, 29, 75, 22, C_DARKCYAN);
  tft.setTextSize(1);
  tft.setTextColor(C_CYAN);
  tft.setCursor(246, 36);
  tft.print(toolsMode == 0 ? "CHANNEL" :
            toolsMode == 1 ? "DIAG" :
            toolsMode == 2 ? "IR" :
            toolsMode == 3 ? "PACKET" : "RADAR");

  if (toolsMode == 0) drawRadarView();
  else if (toolsMode == 1) drawChannelAnalysis();
  else if (toolsMode == 2) drawDiagnostics();
  else if (toolsMode == 3) drawIRMonitor();
  else drawPacketMonitor();

  tft.drawRect(245, 183, 65, 22, C_DARKCYAN);
  tft.setTextColor(scanRunning ? C_YELLOW :
                   toolsMode == 3 ? C_ORANGE :
                   toolsMode == 4 && monitorActive ? C_RED : C_CYAN);
  tft.setCursor(252, 190);
  tft.print(scanRunning ? "BUSY" :
            toolsMode == 2 ? "BLE SCAN" :
            toolsMode == 3 ? "CLEAR" :
            toolsMode == 4 ? (monitorActive ? "STOP" : "START") : "RESCAN");
}

void serviceRadarAnimation() {
  if (currentScreen != TOOLS || toolsMode != 0 || uiDirty) return;
  if (millis() - lastRadarUpdate < 70) return;
  lastRadarUpdate = millis();

  constexpr int16_t cx = 160;
  constexpr int16_t cy = 125;
  constexpr int16_t radius = 68;

  int16_t oldX = cx + static_cast<int16_t>(cosf(previousRadarSweepAngle) * radius);
  int16_t oldY = cy + static_cast<int16_t>(sinf(previousRadarSweepAngle) * radius);
  tft.drawLine(cx, cy, oldX, oldY, C_BG);

  // Restore any rings or blips crossed by the erased sweep line.
  drawRadarElements();

  previousRadarSweepAngle = radarSweepAngle;
  radarSweepAngle += 0.075f;
  if (radarSweepAngle >= TWO_PI) radarSweepAngle -= TWO_PI;

  int16_t newX = cx + static_cast<int16_t>(cosf(radarSweepAngle) * radius);
  int16_t newY = cy + static_cast<int16_t>(sinf(radarSweepAngle) * radius);
  tft.drawLine(cx, cy, newX, newY, C_GREEN);
}

void drawToggle(int16_t y, const char* label, bool enabled) {
  tft.setTextSize(1);
  tft.setTextColor(C_WHITE);
  tft.setCursor(18, y + 10);
  tft.print(label);

  tft.fillRoundRect(235, y, 65, 27, 4, enabled ? C_DARKCYAN : C_PANEL);
  tft.drawRoundRect(235, y, 65, 27, 4, enabled ? C_CYAN : C_GREY);
  tft.setTextColor(enabled ? C_GREEN : C_GREY);
  tft.setCursor(254, y + 10);
  tft.print(enabled ? "ON" : "OFF");
}

void drawSettings() {
  const char* subtitles[3] = {"Scanning and time", "System and hardware", "Live and guard behavior"};
  drawTitle("SETTINGS", subtitles[settingsPage]);

  tft.drawRect(270, 29, 40, 22, C_DARKCYAN);
  tft.setTextColor(C_CYAN);
  tft.setCursor(280, 36);
  tft.printf("%u>", settingsPage + 1);

  if (settingsPage == 0) {
    drawToggle(56, "AUTOMATIC SCANNING", autoScan);
    drawToggle(88, "INCLUDE HIDDEN SSIDS", showHidden);

    tft.setTextColor(C_WHITE);
    tft.setCursor(18, 130);
    tft.print("SCAN INTERVAL");
    tft.drawRoundRect(215, 120, 85, 27, 4, C_DARKCYAN);
    tft.setTextColor(C_CYAN);
    tft.setCursor(238, 130);
    tft.printf("%lus", static_cast<unsigned long>(scanIntervalMs / 1000));

    char timeText[12];
    formatClock(timeText, sizeof(timeText));
    tft.drawRoundRect(18, 153, 284, 25, 4, C_DARKCYAN);
    tft.setTextColor(C_WHITE);
    tft.setCursor(30, 162);
    tft.print("MANUAL CLOCK");
    tft.setTextColor(clockConfigured ? C_GREEN : C_GREY);
    tft.setCursor(230, 162);
    tft.print(timeText);

    tft.setTextColor(C_GREY);
    tft.setCursor(73, 193);
    tft.print("TIME COUNTS WHILE POWERED");
  } else if (settingsPage == 1) {
    drawToggle(57, "RADIO POWER SAVING", radioPowerSave);

    tft.drawRoundRect(35, 96, 250, 28, 4, C_CYAN);
    tft.setTextColor(C_WHITE);
    tft.setCursor(107, 106);
    tft.print("CALIBRATE TOUCH");

    tft.drawRoundRect(35, 132, 250, 28, 4, C_DARKCYAN);
    tft.setCursor(117, 142);
    tft.print("CLEAR AP CACHE");

    tft.drawRoundRect(35, 168, 250, 28, 4, C_RED);
    tft.setTextColor(C_RED);
    tft.setCursor(111, 178);
    tft.print("WIPE KRNL DATA");
  } else {
    drawToggle(57, "ADAPTIVE SCAN CADENCE", adaptiveScan);
    drawToggle(91, "GUARD DETECTION", guardMode);
    tft.setTextColor(C_WHITE);
    tft.setCursor(18, 137);
    tft.printf("WATCHLIST      %u / %u", watchlistCount, MAX_WATCHLIST);
    tft.setCursor(18, 155);
    tft.printf("STABLE SCANS   %u", stableScanCount);
    tft.drawRoundRect(35, 172, 250, 28, 4, baselineReady ? C_GREEN : C_YELLOW);
    tft.setTextColor(baselineReady ? C_GREEN : C_YELLOW);
    tft.setCursor(baselineReady ? 102 : 112, 182);
    tft.print(baselineReady ? "RESET BASELINE" : "LEARNING BASELINE");
  }
}

void renderScreen() {
  if (fullRedraw) {
    tft.fillScreen(C_BG);
    drawHeader();
  } else {
    // Background updates clear only the content area. The header and
    // navigation remain stable, eliminating the visible full-screen reload.
    tft.fillRect(0, HEADER_H, SCREEN_W, NAV_Y - HEADER_H, C_BG);
  }

  switch (currentScreen) {
    case HOME:     drawHome(); break;
    case RECON:    drawRecon(); break;
    case DETAILS:  drawDetails(); break;
    case LOGS:     drawLogs(); break;
    case TOOLS:    drawTools(); break;
    case SETTINGS: drawSettings(); break;
  }

  if (fullRedraw) drawNavigation();
  uiDirty = false;
  fullRedraw = false;
  lastHeaderUpdate = millis();
}

// -------------------------- UI handling --------------------------

void handleTap(int16_t x, int16_t y) {
  addLog("UI", "Tap x%d y%d", x, y);

  if (x >= 286 && y < HEADER_H) {
    if (k17Mood != K17_SCANNING) {
      k17Mood = k17Mood == K17_INSPECT ? K17_IDLE : K17_INSPECT;
      k17Frame = 0;
      drawK17Avatar();
    }
    return;
  }

  if (y >= NAV_Y) {
    uint8_t tab = x / 53;
    if (tab > 5) tab = 5;
    if (monitorActive && tab != TOOLS) stopPacketMonitor();
    currentScreen = static_cast<Screen>(tab);
    fullRedraw = true;
    uiDirty = true;
    return;
  }

  switch (currentScreen) {
    case HOME:
      if (y >= 135 && y <= 195) {
        currentScreen = RECON;
        fullRedraw = true;
        uiDirty = true;
      }
      break;

    case RECON: {
      if (x >= 275 && y >= 25 && y <= 55) {
        uint8_t pages = (visibleAPCount + RECON_ROWS - 1) / RECON_ROWS;
        if (pages == 0) pages = 1;
        reconPage = (reconPage + 1) % pages;
        uiDirty = true;
        break;
      }

      if (y >= 58 && y < 58 + RECON_ROWS * 29) {
        uint8_t row = (y - 58) / 29;
        uint8_t listIndex = reconPage * RECON_ROWS + row;
        if (listIndex < visibleAPCount) {
          selectedAP = sortedAP[listIndex];
          k17Mood = K17_INSPECT;
          currentScreen = DETAILS;
          fullRedraw = true;
          uiDirty = true;
        }
      }
      break;
    }

    case DETAILS:
      if (x >= 260 && y >= 25 && y <= 55) {
        detailsPage = detailsPage == 0 ? 1 : 0;
        uiDirty = true;
      } else if (detailsPage == 1 && selectedAP >= 0) {
        if (x >= 15 && x <= 155 && y >= 155 && y <= 205) {
          toggleWatchlist(apCache[selectedAP].bssid);
          writeConfigBackup();
          uiDirty = true;
        } else if (x >= 165 && x <= 305 && y >= 155 && y <= 205) {
          simulateGuardIncident();
          uiDirty = true;
        }
      }
      break;

    case LOGS:
      if (x >= 250 && y >= 25 && y <= 55) {
        logCount = 0;
        logHead = 0;
        addLog("SYSTEM", "Log buffer cleared");
        uiDirty = true;
      }
      break;

    case TOOLS:
      if (x >= 225 && y >= 25 && y <= 55) {
        if (monitorActive && toolsMode == 4) stopPacketMonitor();
        toolsMode = (toolsMode + 1) % 5;
        uiDirty = true;
      } else if (toolsMode == 0 && x >= 82 && x <= 238 &&
                 y >= 48 && y <= 202) {
        int16_t hit = radarBlipAt(x, y);
        if (hit >= 0) {
          selectedAP = hit;
          detailsPage = 0;
          k17Mood = K17_INSPECT;
          currentScreen = DETAILS;
          fullRedraw = true;
          uiDirty = true;
        }
      } else if (toolsMode == 4 && y >= 140 && y <= 179) {
        if (x >= 8 && x <= 68) {
          monitorChannelHop = false;
          monitorChannel = monitorChannel <= 1 ? 13 : monitorChannel - 1;
          if (monitorActive) esp_wifi_set_channel(monitorChannel, WIFI_SECOND_CHAN_NONE);
          uiDirty = true;
        } else if (x >= 70 && x <= 174) {
          monitorChannelHop = !monitorChannelHop;
          lastMonitorHopAt = millis();
          uiDirty = true;
        } else if (x >= 176 && x <= 234) {
          monitorChannelHop = false;
          monitorChannel = monitorChannel >= 13 ? 1 : monitorChannel + 1;
          if (monitorActive) esp_wifi_set_channel(monitorChannel, WIFI_SECOND_CHAN_NONE);
          uiDirty = true;
        }
      } else if (x >= 235 && y >= 178 && y <= 210 && !scanRunning) {
        if (toolsMode == 2) {
          runBLEScan();
        } else if (toolsMode == 3) {
          irBurstCount = 0;
          lastIRBurstAt = 0;
          lastIREdges = 0;
          lastIRMinLowUs = lastIRMaxLowUs = 0;
          lastIRMinHighUs = lastIRMaxHighUs = 0;
          addLog("IR", "On-screen IR counters cleared");
          uiDirty = true;
        } else if (toolsMode == 4) {
          if (monitorActive) {
            stopPacketMonitor();
          } else if (verifyAccessPin("AUTHORIZE MONITOR")) {
            startPacketMonitor();
          }
          fullRedraw = true;
          uiDirty = true;
        } else {
          startScan();
        }
      }
      break;

    case SETTINGS:
      if (x >= 260 && y >= 25 && y <= 55) {
        settingsPage = (settingsPage + 1) % 3;
        uiDirty = true;
      } else if (settingsPage == 0) {
        if (y >= 52 && y <= 84) {
          autoScan = !autoScan;
          prefs.putBool("autoScan", autoScan);
          writeConfigBackup();
          if (autoScan) nextScanAt = millis();
          uiDirty = true;
        } else if (y >= 85 && y <= 117) {
          showHidden = !showHidden;
          prefs.putBool("hidden", showHidden);
          writeConfigBackup();
          uiDirty = true;
        } else if (y >= 118 && y <= 150) {
          if (scanIntervalMs == 5000) scanIntervalMs = 10000;
          else if (scanIntervalMs == 10000) scanIntervalMs = 20000;
          else if (scanIntervalMs == 20000) scanIntervalMs = 30000;
          else scanIntervalMs = 5000;
          prefs.putULong("interval", scanIntervalMs);
          writeConfigBackup();
          nextScanAt = millis() + scanIntervalMs;
          uiDirty = true;
        } else if (y >= 151 && y <= 180) {
          runTimeEditor();
        }
      } else if (settingsPage == 1) {
        if (y >= 52 && y <= 90) {
          radioPowerSave = !radioPowerSave;
          prefs.putBool("powerSave", radioPowerSave);
          writeConfigBackup();
          WiFi.setSleep(radioPowerSave);
          uiDirty = true;
        } else if (y >= 92 && y <= 128) {
          runCalibration();
        } else if (y >= 129 && y <= 166) {
          memset(apCache, 0, sizeof(apCache));
          apCount = 0;
          visibleAPCount = 0;
          selectedAP = -1;
          addLog("SYSTEM", "AP cache cleared");
          uiDirty = true;
        } else if (y >= 167 && y <= 205) {
          if (verifyAccessPin("AUTHORIZE DATA WIPE")) {
            if (confirmKRNLWipe()) {
              wipeKRNLData();
            } else {
              addLog("SECURITY", "KRNL data wipe cancelled");
              fullRedraw = true;
              uiDirty = true;
            }
          } else {
            fullRedraw = true;
            uiDirty = true;
          }
        }
      } else {
        if (y >= 52 && y <= 88) {
          adaptiveScan = !adaptiveScan;
          prefs.putBool("adaptive", adaptiveScan);
          writeConfigBackup();
          uiDirty = true;
        } else if (y >= 89 && y <= 124) {
          guardMode = !guardMode;
          prefs.putBool("guard", guardMode);
          writeConfigBackup();
          uiDirty = true;
        } else if (y >= 165 && y <= 205 && baselineReady) {
          resetBaseline();
          uiDirty = true;
        }
      }
      break;
  }
}

void serviceTouch() {
  int16_t x;
  int16_t y;
  bool pressed = readTouch(x, y);

  if (pressed && !touchLatched && millis() - lastTouchAt > 120) {
    touchLatched = true;
    lastTouchAt = millis();
    handleTap(x, y);
  }

  if (!pressed) {
    touchLatched = false;
  }
}

// ---------------------------- Startup ----------------------------

void drawProceduralSkull(int16_t cx, int16_t cy, uint16_t color) {
  tft.drawCircle(cx, cy, 34, color);
  tft.drawCircle(cx, cy + 1, 33, color);
  tft.fillTriangle(cx - 27, cy + 15, cx + 27, cy + 15, cx, cy + 51, C_BG);
  tft.drawLine(cx - 27, cy + 15, cx - 17, cy + 43, color);
  tft.drawLine(cx + 27, cy + 15, cx + 17, cy + 43, color);
  tft.drawFastHLine(cx - 17, cy + 43, 35, color);

  tft.fillTriangle(cx - 22, cy - 7, cx - 5, cy - 2, cx - 16, cy + 10, color);
  tft.fillTriangle(cx + 22, cy - 7, cx + 5, cy - 2, cx + 16, cy + 10, color);
  tft.fillTriangle(cx, cy + 5, cx - 5, cy + 18, cx + 5, cy + 18, color);

  for (int8_t i = -2; i <= 2; i++) {
    tft.drawFastVLine(cx + i * 6, cy + 27, 16, color);
  }
  tft.drawFastHLine(cx - 16, cy + 27, 33, color);
}

void drawBootSequence() {
  tft.fillScreen(C_BG);
  tft.drawRect(5, 5, 310, 230, C_CYAN);

  tft.setTextColor(C_CYAN);
  tft.setTextSize(3);
  tft.setCursor(116, 13);
  tft.print("KRNL");

  drawProceduralSkull(160, 82, C_CYAN);

  // Lightweight boot glitch without a large external bitmap asset.
  for (uint8_t frame = 0; frame < 7; frame++) {
    int16_t y = random(35, 135);
    int16_t width = random(40, 170);
    int16_t x = random(20, 300 - width);
    tft.fillRect(x, y, width, random(2, 6), frame & 1 ? C_DARKCYAN : C_BG);
    delay(45);
    drawProceduralSkull(160, 82, C_CYAN);
  }

  tft.setTextColor(C_GREEN);
  tft.setTextSize(1);
  tft.setCursor(105, 139);
  tft.print("SYSTEM AWAKENING");

  const char* stages[] = {
    "DISPLAY LINK",
    "TOUCH INPUT",
    "RECON ENGINE",
    "IR MONITOR",
    "KRNL-17"
  };

  for (uint8_t i = 0; i < 5; i++) {
    tft.setTextSize(1);
    tft.setTextColor(C_GREY);
    tft.setCursor(70, 151 + i * 12);
    tft.print(stages[i]);
    tft.setTextColor(C_GREEN);
    tft.setCursor(225, 151 + i * 12);
    tft.print("OK");
    delay(110);
  }

  delay(500);
}

void setup() {
  Serial.begin(115200);
  delay(300);

  monitorQueue = xQueueCreate(MONITOR_QUEUE_LENGTH, sizeof(MonitorFrame));

  pinMode(PIN_TFT_CS, OUTPUT);
  pinMode(PIN_TOUCH_CS, OUTPUT);
  pinMode(PIN_SD_CS, OUTPUT);
  digitalWrite(PIN_TFT_CS, HIGH);
  digitalWrite(PIN_TOUCH_CS, HIGH);
  digitalWrite(PIN_SD_CS, HIGH);

  SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI);

  tft.begin(10000000);
  tft.setRotation(1);

  touch.begin();
  touch.setRotation(1);

  pinMode(PIN_IR_RECEIVER, INPUT);
  attachInterrupt(digitalPinToInterrupt(PIN_IR_RECEIVER), handleIREdge, CHANGE);

  loadSettings();
  drawBootSequence();

  // Raw touch reception was verified separately, but every resistive panel
  // has different limits/orientation. Force calibration once for this
  // firmware version before any mapped UI hit-testing is attempted.
  if (!calibrationValid) {
    runCalibration();
    while (touch.touched()) delay(10);
  }

  // The ESP32 has no battery-backed RTC, so offer manual time entry on
  // every boot before session files and scan timestamps are created.
  runTimeEditor();
  while (touch.touched()) delay(10);

  // Mount storage before the lock screen so failed boot-time attempts can
  // be preserved in the security log. Time entry still appears first on
  // every reset and every power-on.
  sdReady = initializeSD();
  configureOrUnlock();
  writeConfigBackup();
  while (touch.touched()) delay(10);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false);
  WiFi.setSleep(radioPowerSave);
  delay(100);

  addLog("BOOT", "KRNL firmware started");
  addLog("SYSTEM", "Free heap: %lu bytes",
         static_cast<unsigned long>(ESP.getFreeHeap()));
  addLog("SYSTEM", "Passive 2.4 GHz mode");
  addLog("MONITOR", monitorQueue ?
         "Packet queue ready; receive-only" :
         "Packet queue allocation failed");
  addLog("IR", digitalRead(PIN_IR_RECEIVER) ?
         "TSOP1838B ready on GPIO21" :
         "TSOP input LOW: verify OUT/GND/VS pinout");
  addLog("SYSTEM", sdReady ? "SD ready: %s" : "SD initialization failed",
         sdReady ? sdLogPath : "");
  flushSDLogs(true);

  rebuildSortedAPList();
  renderScreen();
}

void loop() {
  serviceScanner();
  servicePacketMonitor();
  serviceIRReceiver();
  serviceTouch();
  flushSDLogs(false);

  if (uiDirty) {
    renderScreen();
  } else {
    serviceRadarAnimation();
    serviceLogsWaveform();
    serviceK17Animation();
  }

  if (!uiDirty && millis() - lastHeaderUpdate >= 1000) {
    // Only refresh the header for uptime/status; avoids full-screen flicker.
    drawHeader();
    lastHeaderUpdate = millis();
  }

  delay(5);
}
