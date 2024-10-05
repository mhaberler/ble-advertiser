#include <NimBLEDevice.h>
#include <ArduinoJson.h>

static const char* DEFAULT_MAC = "C0:DE:BA:BE:00:01";

std::string hexToBytes(const char* hex) {
    std::string bytes;
    if (!hex) return bytes;
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        Serial.println("[WARN] hexToBytes: odd-length hex string, ignoring last nibble");
        len--;
    }
    bytes.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        char byteStr[3] = {hex[i], hex[i + 1], '\0'};
        char* end;
        uint8_t b = (uint8_t)strtol(byteStr, &end, 16);
        if (end != byteStr + 2) {
            Serial.printf("[WARN] hexToBytes: invalid hex at offset %u: '%s'\n", i, byteStr);
        }
        bytes += (char)b;
    }
    return bytes;
}

void setup() {
    Serial.begin(115200);
    NimBLEDevice::init("Replay");
    Serial.println("Ready. Send JSON command...");
}

void loop() {
    if (Serial.available() > 0) {
        String input = Serial.readStringUntil('\n');
        JsonDocument doc;
        DeserializationError error = deserializeJson(doc, input);

        if (error) {
            Serial.print("JSON Error: ");
            Serial.println(error.c_str());
            return;
        }

        Serial.println("--- Command Received ---");
        serializeJsonPretty(doc, Serial);
        Serial.println("\n------------------------");

        const char* macStr      = doc["mac"] | DEFAULT_MAC;
        const char* deviceName  = doc["name"] | "";
        uint16_t appearance     = doc["appearance"] | 0;
        unsigned long duration  = doc["duration"] | 1000;

        NimBLEAdvertising* pAdv = NimBLEDevice::getAdvertising();
        if (pAdv->isAdvertising()) pAdv->stop();

        NimBLEDevice::setOwnAddr(NimBLEAddress(macStr, BLE_OWN_ADDR_RANDOM));
        NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);

        NimBLEAdvertisementData advData;
        if (!doc["adv"].isNull()) {
            const char* advHex = doc["adv"];
            std::string advBytes = hexToBytes(advHex);
            advData.addData(
                reinterpret_cast<const uint8_t*>(advBytes.data()),
                advBytes.length()
            );
        }

        if (!doc["service_uuid"].isNull() && !doc["service_data"].isNull()) {
            const char* srvUuidStr = doc["service_uuid"];
            std::string srvDataBytes = hexToBytes(doc["service_data"]);
            const char* srvDataHex = doc["service_data"];

            NimBLEUUID srvUuid{std::string(srvUuidStr)};

            Serial.printf("[BLE] Service UUID: %s (%d-bit) | Data: %s (%u bytes)\n",
                          srvUuid.toString().c_str(), srvUuid.bitSize(),
                          srvDataHex, srvDataBytes.length());
            if (!advData.setServiceData(srvUuid, srvDataBytes)) {
                Serial.println("[ERR] setServiceData failed - data may be too long");
            }
        }

        NimBLEAdvertisementData scanRspData;
        if (strlen(deviceName) > 0) {
            scanRspData.setName(deviceName);
        }

        if (!doc["scan_raw"].isNull()) {
            std::string scanBytes = hexToBytes(doc["scan_raw"]);
            scanRspData.addData(
                reinterpret_cast<const uint8_t*>(scanBytes.data()),
                scanBytes.length()
            );
        }

        if (appearance > 0) {
            scanRspData.setAppearance(appearance);
        }
        pAdv->setScanResponseData(scanRspData);
        pAdv->setAdvertisementData(advData);

        pAdv->start();
        Serial.printf("Broadcasting as [%s] Name: [%s]\n", macStr, deviceName);

        if (duration > 0) {
            delay(duration);
            pAdv->stop();
            Serial.println("Duration reached. Stopped.");
        } else {
            Serial.println("Infinite broadcast started...");
        }
    }
}