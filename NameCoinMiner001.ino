/**
   @file
   @brief Main header includes for the Namecoin Mining Device

   This file contains all necessary library includes for the Namecoin mining device.
   The included libraries provide the following functionality:

   - WiFi.h: Core WiFi functionality for network connectivity
   - WiFiClient.h: Client implementation for WiFi connections
   - WebServer.h: Web server functionality for configuration interface
   - ESPmDNS.h: Multicast DNS for network service discovery
   - mbedtls/sha256.h: SHA-256 cryptographic hash function implementation
   - ArduinoJson.h: JSON parsing and creation functionality
   - Preferences.h: Persistent storage for device configuration
   - WiFiClientSecure.h: Secure WiFi client for encrypted connections
   - AESLib.h: AES encryption functionality
   - esp_random.h: Hardware random number generator
   - base64.h: Base64 encoding/decoding utilities
   - esp_task_wdt.h: Watchdog timer functionality
   - UPnP_Generic.h: Universal Plug and Play functionality

   These libraries enable the device to:
   - Connect to WiFi networks
   - Provide a web interface for configuration
   - Perform cryptographic operations for mining
   - Store persistent configuration data
   - Establish secure connections to mining pools
   - Generate random numbers for encryption
   - Monitor system stability
   - Handle network discovery and port forwarding
*/
#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <mbedtls/sha256.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <WiFiClientSecure.h>
#include <AESLib.h>
/*************  ✨ Codeium Command 🌟  *************/
#include <esp_random.h> // ESP32 random number generator
#include <base64.h> // Base64 encoding and decoding
#include "esp_task_wdt.h"
#include <UPnP_Generic.h> // https://github.com/khoih-prog/UPnP_Generic

/*************  ✨ Codeium Command 🌟  *************/
// Function declarations

/**
  /******  e1dc636b-a366-4afb-a0a8-8ba6b31ef529  *******/
* @brief Handle the certificate download request
*
* This function is called when the / downloadCert endpoint is accessed.
* It downloads the certificate from the pool server and saves it to
* the preferences.
* /
// Function Declarations
void handleDownloadCert();
/******  3f8fd27d-5385-4ca4-b78f-61fab36135fb  *******/
String primaryDNS;
String secondaryDNS;
String downloadCertificate(const char* serverAddress, int serverPort);
void generateRandomIV(byte* iv, size_t ivLength);
void deriveKey(const char* passphrase, byte* key);
void encryptWalletAddress(const char* walletAddress, const char* passphrase);
String decryptWalletAddress(const char* passphrase);
void handleRoot();
void handleSave();
void handleStart();
void handleStop();
void handleStatus();
void hexStringToBytes(const String& hexString, byte* byteArray);
void reverseBytes(byte* byteArray, int length);
void nbitsToTarget(const String& nbitsHex, byte* target);
void calculateMerkleRoot(const JsonArray &txHashes, byte *merkleRoot);
bool processMiningJob(const String& response, String& jobId, String& prevHash, String& version, String& nbits, String& ntime, JsonArray& merkleBranch);
bool submitShare(WiFiClientSecure& poolClient, const String& walletAddress, const String& jobId, const String& ntime, unsigned long currentNonce, const String& merkleRoot);
bool mineBlock(WiFiClientSecure& poolClient);
// Debug Level from 0 to 4
#define _DDNS_GENERIC_LOGLEVEL_ 1
#define LISTEN_PORT 5933
#define LEASE_DURATION 36000 // seconds
#define FRIENDLY_NAME ARDUINO_BOARD "Badger32" // this name will appear in your router port forwarding section
// setting PWM properties
const int freq = 5000;
const int ledChannel = 0;
const int resolution = 10; //Resolution 8, 10, 12, 15 bits. Select 10 => 1024 steps
#define LED_REVERSED false
#define LED_ON 100
#define LED_OFF 0

#define LED_PIN 2 // LED_BUILTIN
// AP Configuration
const char* apSSID = "Badger_32_Setup";
const char* apPassword = "1234567890";
const int delayval = 10;
// 0 <= percentage <= 100
void setPower(uint32_t percentage)
{
  long pwm_val = map(percentage, LED_OFF, LED_ON, 0, 1023);

  if (pwm_val > 1023)
  {
    pwm_val = 1023;
  }

  ledcWrite(ledChannel, pwm_val);
}

void fadeOn()
{
  int start = 0;
  int end = 100;
  int step = 1;

  if (LED_REVERSED)
  {
    start = 100;
    end = 0;
    step = -1;
  }

  for (int i = start; i != end; i += step)
  {
    setPower(i);
    delay(delayval);
  }
}

void fadeOff()
{
#if LED_REVERSED
  for (int i = 0; i < 100; i++)
#else
  for (int i = 100; i >= 0; i--)
#endif
  {
    setPower(i);
    delay(delayval);
  }
}

void showLED()
{
  for (int i = 0; i < 2; i++)
  {
    fadeOn();
    fadeOff();
  }
}
// Configuration Variables (Loaded from Preferences)
String wifiSSID;
String wifiPassword;
String walletAddress;
String poolServer;
int poolPort;
String ddnsDomain; // New variable
String ddnsToken; // New variable
String poolCert; // Certificate loaded from preferences

// Mining variables
unsigned long hashCount = 0;
String deviceName = "Badger the NMC Miner";
bool miningEnabled = false; // Initialize to false
unsigned long currentNonce = 0;
byte preHeader[76]; // Pre-calculated header

WebServer server(80);
Preferences preferences;
WiFiClient client;
WiFiClientSecure poolClient; // Use WiFiClientSecure for secure download and mining
AESLib aesLib;
const unsigned long certificateDownloadTimeout = 5000; // 5 seconds timeout

void setup() {
  Serial.begin(115200);
  Serial.println("Starting setup...");
  uint32_t chipId = 0;
  for (int i = 0; i < 17; i = i + 8) {
    chipId |= ((ESP.getEfuseMac() >> (40 - i)) & 0xff) << i;
  }
  while (!Serial && millis() < 5000);
#if ( ARDUINO_ESP32S2_DEV || ARDUINO_FEATHERS2 || ARDUINO_ESP32S2_THING_PLUS || ARDUINO_MICROS2 || ARDUINO_METRO_ESP32S2 || ARDUINO_MAGTAG29_ESP32S2 || ARDUINO_FUNHOUSE_ESP32S2 || ARDUINO_ADAFRUIT_FEATHER_ESP32S2_NOPSRAM)
#warning Using ESP32_S2
  Serial.printf("ESP32 Chip model = %s Rev %d\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("This chip has %d cores\n", ESP.getChipCores());
  Serial.print("Chip ID: ");
  Serial.println(chipId);

  delay(3000);
#endif
  // Initialize Preferences
  preferences.begin("miner_config");
  Serial.println("Preferences initialized");

  // Initialize Web Server Routes
  server.on("/", handleRoot); // Setup Page
  server.on("/save", handleSave); // Save Configuration
  server.on("/downloadCert", handleDownloadCert); // Download Certificate
  server.on("/start", HTTP_POST, handleStart);
  server.on("/stop", HTTP_POST, handleStop);
  server.on("/status", HTTP_GET, handleStatus);
  server.begin();
  Serial.println("Web server started");

  // Load Configuration from Preferences
  wifiSSID = preferences.getString("wifiSSID", "");
  wifiPassword = preferences.getString("wifiPassword", "");
  walletAddress = preferences.getString("walletAddress", "");
  poolServer = preferences.getString("poolServer", "");
  poolPort = preferences.getInt("poolPort", 0);
  poolCert = preferences.getString("poolCert", "");
  primaryDNS = preferences.getString("primaryDNS", "");
  secondaryDNS = preferences.getString("secondaryDNS", "");
  ddnsDomain = preferences.getString("ddnsDomain", ""); // Load DDNS domain
  ddnsToken = preferences.getString("ddnsToken", ""); // Load DDNS token

  Serial.println("Configuration loaded from preferences");
  Serial.println("Setup complete");
}
void loop() {
  if (WiFi.status() != WL_CONNECTED && wifiSSID.length() > 0) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(wifiSSID);
    WiFi.begin(wifiSSID.c_str(), wifiPassword.c_str());
    // Wait for connection
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 10) {
      delay(500);
      Serial.print(".");
      attempts++;
    }
    Serial.println("");
    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("WiFi connected");
      // Set DNS servers
      IPAddress dns1, dns2;
      if (primaryDNS.length() > 0 && dns1.fromString(primaryDNS.c_str())) {
        Serial.print("Using primary DNS from config: ");
        Serial.println(dns1);
      } else {
        dns1.fromString("8.8.4.4");
        Serial.println("Using default primary DNS: 8.8.4.4");
      }
      if (secondaryDNS.length() > 0 && dns2.fromString(secondaryDNS.c_str())) {
        Serial.print("Using secondary DNS from config: ");
        Serial.println(dns2);
      } else {
        dns2.fromString("9.9.9.9");
        Serial.println("Using default secondary DNS: 9.9.9.9");
      }
      WiFi.config(WiFi.localIP(), WiFi.gatewayIP(), WiFi.subnetMask(), dns1, dns2);
      Serial.print("DNS Servers set to: ");
      Serial.print(dns1);
      Serial.print(", ");
      Serial.println(dns2);
    } else {
      Serial.println("Failed to connect to WiFi.");
    }
  }

  //delay(100);

  server.handleClient();

  if (WiFi.status() == WL_CONNECTED) {
    if (poolCert.length() > 0) {
      poolClient.setCACert(poolCert.c_str()); // Set the downloaded certificate
    } else {
      Serial.println("Warning: Pool certificate not loaded.");
    }
    if (poolClient.connect(poolServer.c_str(), poolPort)) {
      Serial.println("Connected to mining pool (secure)");

      if (miningEnabled) {
        // Indicate mining start
        Serial.println("Mining started, brightening LED...");
        fadeOn(); // Or setPower(LED_ON)

        unsigned long startTime = millis();
        unsigned long hashCountThisSecond = 0;

        while (miningEnabled) {
          if (!mineBlock(poolClient)) { // Encapsulated mining logic
            Serial.println("Connection to pool lost or error in mining. Reconnecting...");
            delay(5000); // Wait before reconnecting
            break; // Break inner mining loop to reconnect in outer loop
          }

          hashCountThisSecond++; // Increment hash counter

          if (millis() - startTime >= 1000) {
            Serial.print("Hashes per second: ");
            Serial.println(hashCountThisSecond);
            startTime = millis();
            hashCountThisSecond = 0;
          }
        }

        // Indicate mining stopped (either due to error or miningEnabled becoming false)
        Serial.println("Mining stopped, dimming LED...");
        fadeOff(); // Or setPower(LED_OFF)

        esp_task_wdt_reset(); // Watchdog reset to prevent crashes
        poolClient.stop(); // Close pool connection when mining loop ends or reconnecting
      } else {
        // If not mining, keep the pool connection alive if needed for other tasks
        if (poolClient.connected()) {
          Serial.println("Pool connection active but not mining.");
        }
      }
    } else {
      Serial.println("Failed to connect to mining pool (secure). Retrying...");
      Serial.println("Error: " + String(poolClient.lastError()));
      delay(5000); // Wait before retrying secure connection
    }
  } else {
    Serial.println("WiFi not connected");
    // Handle WiFi connection loss or initial setup via AP
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("Starting AP mode for initial setup or reconfiguration...");
      WiFi.softAP(apSSID, apPassword);
      IPAddress IP = WiFi.softAPIP();
      Serial.print("AP IP address: ");
      Serial.println(IP);
    }
    delay(5000); // Wait before checking WiFi status again
  }

  DDNSGeneric.update(555000);
  uPnP->updatePortMappings(600000); // 10 minutes
}
// Function to handle the certificate download request
void handleDownloadCert() {
  Serial.println("Downloading certificate");
  String poolString = server.arg("pool");
  int colonIndex = poolString.indexOf(':');
  if (colonIndex == -1) {
    server.send(400, "text/plain", "Invalid pool format");
    return;
  }

  String poolAddress = poolString.substring(0, colonIndex);
  int poolPort = poolString.substring(colonIndex + 1).toInt();

  String currentCert = downloadCertificate(poolAddress.c_str(), poolPort);

  if (currentCert.length() > 0) {
    preferences.putString("poolCert", currentCert);
    server.send(200, "text/plain", "Certificate downloaded successfully");
  } else {
    server.send(500, "text/plain", "Certificate download failed");
  }
}

String downloadCertificate(const char* serverAddress, int serverPort) {
  Serial.println("Connecting to server for certificate download (secure)");

  WiFiClientSecure client; // Use a local client instance for this function

  if (!client.connect(serverAddress, serverPort)) {
    Serial.println("Secure connection failed to server: " + String(serverAddress) + ":" + String(serverPort));
    Serial.println("Error: " + String(client.lastError()));
    return "";
  }
  Serial.println("Connected to server for certificate download (secure)");

  String certificate = "";
  bool certificateFound = false;
  unsigned long startTime = millis();
  const String beginMarker = "-----BEGIN CERTIFICATE-----";
  const String endMarker = "-----END CERTIFICATE-----";
  String receivedData = "";

  while (millis() - startTime < certificateDownloadTimeout) {
    if (client.available()) {
      char buffer[128];
      int bytesRead = client.readBytes(buffer, sizeof(buffer) - 1);
      if (bytesRead > 0) {
        buffer[bytesRead] = '\0'; // Null-terminate the buffer
        receivedData += buffer;

        int beginIndex = receivedData.indexOf(beginMarker);
        int endIndex = receivedData.indexOf(endMarker);

        if (beginIndex != -1 && endIndex > beginIndex) {
          certificate = receivedData.substring(beginIndex, endIndex + endMarker.length());
          Serial.println("\nExtracted Certificate:\n" + certificate);
          certificateFound = true;
          break;
        }
      }
    }
    delay(10);
  }

  client.stop(); // Close the secure connection
  Serial.println("Certificate download connection closed");

  if (!certificateFound) {
    Serial.println("Certificate not found or download timed out.");
    return "";
  }
  return certificate;
}
// Function to generate a random Initialization Vector (IV) for AES encryption
void generateRandomIV(byte* iv, size_t ivLength) {
  for (size_t i = 0; i < ivLength; i++) {
    iv[i] = (byte)esp_random();
  }
}

// Function to derive a key from a passphrase using SHA-256
void deriveKey(const char* passphrase, byte* key) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, (const unsigned char*)passphrase, strlen(passphrase));
  mbedtls_sha256_finish_ret(&ctx, key);
  mbedtls_sha256_free(&ctx);
}

// Function to encrypt the wallet address using AES
void encryptWalletAddress(const char* walletAddress, const char* passphrase) {
  byte key[32];
  deriveKey(passphrase, key);

  byte iv[16];
  generateRandomIV(iv, sizeof(iv));

  String walletAddressStr = String(walletAddress);
  String encrypted = aesLib.encrypt(walletAddressStr, key, sizeof(key) * 8, iv);

  preferences.putString("encryptedWalletAddress", encrypted);
  preferences.putBytes("iv", iv, sizeof(iv));
}

// Function to decrypt the wallet address using AES
String decryptWalletAddress(const char* passphrase) {
  String encryptedWalletAddress = preferences.getString("encryptedWalletAddress", "");
  if (encryptedWalletAddress.length() == 0) {
    return ""; // No encrypted wallet address found
  }

  byte iv[16];
  preferences.getBytes("iv", iv, sizeof(iv));

  byte key[32];
  deriveKey(passphrase, key);

  String decrypted = aesLib.decrypt(encryptedWalletAddress, key, sizeof(key) * 8, iv);
  return decrypted;
}

// --- Mining Logic Functions ---

// Function to process a mining job notification from the pool
bool processMiningJob(const String& response, String& jobId, String& prevHash, String& version, String& nbits, String& ntime, JsonArray& merkleBranch) {
  DynamicJsonDocument doc(computeJsonCapacity(response)); // Adjust size as needed
  DeserializationError error = deserializeJson(doc, response);
  if (error) {
    Serial.print("deserializeJson() failed: ");
    Serial.println(error.c_str());
    return false;
  }

  if (doc.containsKey("error")) {
    Serial.println("Pool error: " + doc["error"].as<String>());
    return false;
  }

  if (doc.containsKey("method") && doc["method"] == "mining.notify") {
    JsonArray params = doc["params"].as<JsonArray>();

    if (params.size() != 9) {
      Serial.println("Invalid job: Incorrect number of parameters.");
      return false;
    }

    jobId = params[0].as<String>();
    prevHash = params[1].as<String>();
    version = params[5].as<String>();
    nbits = params[6].as<String>();
    ntime = params[7].as<String>();
    merkleBranch = params[4].as<JsonArray>();

    if (prevHash.length() != 64 || version.length() != 8 || nbits.length() != 8 || ntime.length() != 8) {
      Serial.println("Invalid Job: incorrect hex string length");
      return false;
    }

    if (merkleBranch.size() == 0) {
      Serial.println("Invalid Job: Merkle branch is empty");
      return false;
    }

    for (JsonVariant value : merkleBranch) {
      if (!value.is<String>() || value.as<String>().length() != 64) {
        Serial.println("Invalid Job: Invalid Merkle Branch");
        return false;
      }
    }
    return true;
  }
  return false; // Not a mining.notify job
}
bool submitShare(WiFiClientSecure& poolClient, const String& walletAddress, const String& jobId, const String& ntime, unsigned long currentNonce, const String& merkleRoot) {
  String share = "{\"id\": 2, \"method\": \"mining.submit\", \"params\": [\"" + walletAddress + "\", \"" + jobId + "\", \"" + merkleRoot + "\", \"" + ntime + "\", \"" + String(currentNonce) + "\"]}";
  poolClient.write((const uint8_t*)share.c_str(), share.length());
  poolClient.write("\n");
  Serial.println("Submitted share: " + share);

  unsigned long shareResponseTimeout = millis() + certificateDownloadTimeout;
  while (millis() < shareResponseTimeout) {
    if (poolClient.available()) {
      String shareResponse = poolClient.readStringUntil('\n');
      Serial.println("Share response: " + shareResponse);

      DynamicJsonDocument shareDoc(computeJsonCapacity(shareResponse));
      DeserializationError shareError = deserializeJson(shareDoc, shareResponse);
      if (shareError) {
        Serial.println("Error parsing share response: " + String(shareError.c_str()));
        return false;
      } else if (shareDoc.containsKey("error")) {
        Serial.println("Share submission error: " + shareDoc["error"].as<String>());
        return false;
      } else if (shareDoc.containsKey("result") && shareDoc["result"].as<bool>()) {
        Serial.println("Share accepted!");
        return true;
      } else {
        Serial.println("Share rejected or unknown response.");
        return false;
      }
    }
    delay(10); // Small delay to prevent busy waiting
  }
  Serial.println("No share response received in time.");
  return false; // Timeout

}

// Function to perform the mining loop for a single block job
bool mineBlock(WiFiClientSecure& poolClient) {
  static unsigned long hashCountThisSecond = 0;
  static unsigned long startTime = millis();
  String jobId, prevHash, version, nbits, ntime;
  JsonArray merkleBranch;

#define MINING_SUBSCRIBE_TIMEOUT 10000 // 10 seconds timeout for subscribe

  poolClient.println("{\"id\": 1, \"method\": \"mining.subscribe\", \"params\":}");

  unsigned long subscribeTimeout = millis() + MINING_SUBSCRIBE_TIMEOUT;
  String response = "";
  while (millis() < subscribeTimeout) {
    if (poolClient.available()) {
      response = poolClient.readStringUntil('\n');
      Serial.println("Received: " + response);
      break; // Got subscribe response, proceed
    }
    delay(10);
  }

  if (response.isEmpty()) {
    Serial.println("Timeout on subscribe response.");
    return false;
  }

  if (!processMiningJob(response, jobId, prevHash, version, nbits, ntime, merkleBranch)) {
    Serial.println("Failed to process mining job from subscribe response.");
    return false;
  }

  byte prevHashBytes[32];
  hexStringToBytes(prevHash, prevHashBytes);
  reverseBytes(prevHashBytes, 32);

  byte blockHeader[80];
  memset(blockHeader, 0, 80);

  uint32_t versionInt = strtoul(version.c_str(), nullptr, 16);
  blockHeader[0] = (versionInt >> 0) & 0xFF;
  blockHeader[1] = (versionInt >> 8) & 0xFF;
  blockHeader[2] = (versionInt >> 16) & 0xFF;
  blockHeader[3] = (versionInt >> 24) & 0xFF;

  memcpy(blockHeader + 4, prevHashBytes, 32);

  // Calculate Merkle Root
  byte merkleRootBytes[32];
  calculateMerkleRoot(merkleBranch, merkleRootBytes);
  String merkleRootHex;
  for (int i = 0; i < 32; i++) {
    char hex[3];
    sprintf(hex, "%02x", merkleRootBytes[i]);
    merkleRootHex += hex;
  }
  // reverseBytes((byte*)merkleRootHex.c_str(), merkleRootHex.length()); // Reverse for display if needed - Removed for now, will handle reversal in submitShare if needed

  memcpy(blockHeader + 36, merkleRootBytes, 32);

  uint32_t ntimeInt = strtoul(ntime.c_str(), nullptr, 16);
  blockHeader[68] = (ntimeInt >> 0) & 0xFF;
  blockHeader[69] = (ntimeInt >> 8) & 0xFF;
  blockHeader[70] = (ntimeInt >> 16) & 0xFF;
  blockHeader[71] = (ntimeInt >> 24) & 0xFF;

  hexStringToBytes(nbits, blockHeader + 72);

  currentNonce = 0;
  while (miningEnabled) {
    blockHeader[76] = (currentNonce >> 0) & 0xFF;
    blockHeader[77] = (currentNonce >> 8) & 0xFF;
    blockHeader[78] = (currentNonce >> 16) & 0xFF;
    blockHeader[79] = (currentNonce >> 24) & 0xFF;

    // Use SHA-256 hashing for Namecoin
    byte hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, blockHeader, 80);
    mbedtls_sha256_finish_ret(&ctx, hash);

    // Double SHA-256
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, hash, 32);
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    reverseBytes(hash, 32);

    hashCount++;
    currentNonce++;

    byte target[32];
    nbitsToTarget(nbits, target);

    bool valid = true;
    for (int i = 0; i < 32; i++) {
      if (hash[i] > target[i]) {
        valid = false;
        break;
      } else if (hash[i] < target[i]) {
        break;
      }
    }

    if (valid) {
      // No need to recalculate Merkle Root here, using the one from earlier
      String submitMerkleRootHex = merkleRootHex;
      // Reverse for submission if needed - Check pool requirements
      // reverseBytes((byte*)submitMerkleRootHex.c_str(), submitMerkleRootHex.length());

      if (submitShare(poolClient, walletAddress, jobId, ntime, currentNonce, submitMerkleRootHex)) {
        return true; // Share accepted, job done for this block
      } else {
        return false; // Share rejected or error submitting
      }
    }
    hashCountThisSecond++;

    if (millis() - startTime >= 1000) {
      Serial.print("Hashes per second in mineBlock: ");
      Serial.println(hashCountThisSecond);
      startTime = millis();
      hashCountThisSecond = 0;
    }

    // Check for new messages from pool
    if (poolClient.available()) {
      String newMessage = poolClient.readStringUntil('\n');
      Serial.println("New message from pool: " + newMessage);
      // Process new job if needed
      String newJobId, newPrevHash, newVersion, newNbits, newNtime;
      JsonArray newMerkleBranch;
      if (processMiningJob(newMessage, newJobId, newPrevHash, newVersion, newNbits, newNtime, newMerkleBranch)) {
        Serial.println("New job received, restarting mining process");
        return true; // Restart mining with new job
      }
    }

    // Check for watchdog reset
    if (currentNonce % 10000 == 0) {
      esp_task_wdt_reset();
    }
  }
  return true; // Mining loop exited normally
}
// Function to calculate Merkle root
void calculateMerkleRoot(const JsonArray &txHashes, byte *merkleRoot) {
  if (txHashes.size() == 0) {
    Serial.println("Warning: No transaction hashes provided. Merkle root set to zero hash.");
    memset(merkleRoot, 0, 32);
    return;
  }

  if (txHashes.size() == 1) {
    String firstHash = txHashes[0].as<String>();
    hexStringToBytes(firstHash, merkleRoot);
    // reverseBytes(merkleRoot, 32); // Reversal happens at the end
    return;
  }

  // Calculate initial capacity for the DynamicJsonDocument
  size_t numHashes = txHashes.size();
  // Estimate size per hash string in JSON (including overhead)
  size_t capacityPerHash = 80;
  size_t initialCapacity = numHashes * capacityPerHash + 512; // Add some extra for the JSON structure

  // Create a dynamic array to hold the current level of hashes
  DynamicJsonDocument doc(initialCapacity);
  JsonArray currentLevel = doc.to<JsonArray>();
  for (const String& hashStr : txHashes) {
    currentLevel.add(hashStr);
  }

  while (currentLevel.size() > 1) {
    // Estimate capacity for the next level (can be similar to the current level's initial estimate)
    DynamicJsonDocument nextLevelDoc(initialCapacity);
    JsonArray nextLevel = nextLevelDoc.to<JsonArray>();

    for (int i = 0; i < currentLevel.size(); i += 2) {
      String hash1Str = currentLevel[i].as<String>();
      String hash2Str;

      if (i + 1 < currentLevel.size()) {
        hash2Str = currentLevel[i + 1].as<String>();
      } else {
        hash2Str = hash1Str; // Duplicate the last hash if the count is odd
      }

      byte hash1Bytes[32];
      byte hash2Bytes[32];
      byte combinedHash[64];
      byte resultHash[32];

      hexStringToBytes(hash1Str, hash1Bytes);
      // reverseBytes(hash1Bytes, 32); // Reversal happens at the end
      hexStringToBytes(hash2Str, hash2Bytes);
      // reverseBytes(hash2Bytes, 32); // Reversal happens at the end

      memcpy(combinedHash, hash1Bytes, 32);
      memcpy(combinedHash + 32, hash2Bytes, 32);

      mbedtls_sha256_context ctx;
      mbedtls_sha256_init(&ctx);
      mbedtls_sha256_starts_ret(&ctx, 0);
      mbedtls_sha256_update_ret(&ctx, combinedHash, 64);
      mbedtls_sha256_finish_ret(&ctx, resultHash);

      mbedtls_sha256_init(&ctx);
      mbedtls_sha256_starts_ret(&ctx, 0);
      mbedtls_sha256_update_ret(&ctx, resultHash, 32);
      mbedtls_sha256_finish_ret(&ctx, resultHash);
      mbedtls_sha256_free(&ctx);

      byte resultHashStr[65]; // 32 bytes * 2 hex chars + null terminator
      for (int j = 0; j < 32; j++) {
        sprintf((char*)resultHashStr + (j * 2), "%02x", resultHash[j]);
      }
      resultHashStr[64] = 0; // Null terminate

      nextLevel.add((const char*)resultHashStr);
    }
    currentLevel = nextLevel;
  }

  // The final hash in currentLevel is the Merkle root
  String merkleRootStr = currentLevel[0].as<String>();
  hexStringToBytes(merkleRootStr, merkleRoot);
  reverseBytes(merkleRoot, 32); // Ensure correct byte order for the block header
}
// --- Utility Functions ---
// Function to convert a hex string to a byte array
void hexStringToBytes(const String& hexString, byte* byteArray) {
  if (hexString.length() % 2 != 0) {
    Serial.println("Error: Hex string has an odd length. Cannot convert to bytes.");
    // You might want to handle this error differently, such as returning an error code
    // or throwing an exception if your project uses them. For now, we'll just exit.
    return;
  }

  for (int i = 0; i < hexString.length(); i += 2) {
    unsigned int byteValue;
    sscanf(hexString.substring(i, i + 2).c_str(), "%02x", &byteValue);
    byteArray[i / 2] = static_cast<byte>(byteValue);
  }
}

// Function to convert nbits to target
void nbitsToTarget(const String& nbitsHex, byte* target) {
  memset(target, 0, 32); // Initialize target to 0
  byte nbitsBytes[4];
  hexStringToBytes(nbitsHex, nbitsBytes);
  int exponent = nbitsBytes[0];
  int coefficient = (nbitsBytes[1] << 16) | (nbitsBytes[2] << 8) | nbitsBytes[3];

  if (exponent <= 3) {
    int shift = 8 * (3 - exponent);
    coefficient >>= shift;
    memcpy(target + 29, &coefficient, 3);
  } else {
    int shift = 8 * (exponent - 3);
    coefficient <<= shift;
    memcpy(target + 32 - (shift / 8) - 3, &coefficient, 3);
  }
}

// Function to compute JSON capacity
size_t computeJsonCapacity(const String& json) {
  // Start with a reasonable base capacity
  size_t capacity = 512;

  // Estimate capacity based on the length of the JSON string
  // Use a multiplier to account for structural characters and overhead
  capacity += json.length() * 2; // You can adjust the multiplier

  // Add extra capacity based on the estimated number of elements
  // This is a very rough estimate based on the occurrences of '{', '[', and ','
  int elementCount = 0;
  for (char c : json) {
    if (c == '{' || c == '[' || c == ',') {
      elementCount++;
    }
  }
  capacity += elementCount * 50; // Add some extra per potential element

  // Add a safety margin
  capacity += 256;

  // Ensure a minimum capacity
  if (capacity < 1024) {
    capacity = 1024;
  }

  return capacity;
}
