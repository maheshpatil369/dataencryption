/*
 * AUV_Provision.ino  -  initialise / inspect the boot-epoch storage of a board
 * ---------------------------------------------------------------------------
 * Run ONCE on every STM32 before its real firmware, and again only if the
 * board reports NVM_INVALID (blank or fully erased flash).
 *
 * Open the Serial Monitor at 115200, line ending "Newline", then type:
 *   STATUS        show the storage address and the highest stored epoch
 *   PROVISION     create the store (or move it forward; never backwards)
 *   BOOTTEST      simulate one boot: epoch must go up by exactly 1
 *
 * IMPORTANT: if storage was blank, the keys on this board must be FRESHLY
 * generated (gen_keys.py) - otherwise old nonces could be reused.
 * ---------------------------------------------------------------------------
 */
    #include <AUV_Security.h>

AUV_DefaultFlash flash;
AUV_NonceManager nm;
String line;

static void status() {
#if defined(STM32F1xx)
    Serial.print(F("Epoch log pages at 0x")); Serial.print(flash.pageAddress(0), HEX);
    Serial.print(F(" and 0x")); Serial.println(flash.pageAddress(1), HEX);
#endif
    Serial.print(F("Layout check: ")); Serial.println(AUV_statusName(flash.checkLayout()));
    uint32_t e = nm.inspect(flash);
    Serial.print(F("Highest stored epoch: ")); Serial.println(e);
    if (e == 0) Serial.println(F("-> storage is blank/invalid: type PROVISION"));
}

void setup() {
    Serial.begin(115200);
    while (!Serial && millis() < 3000) {}
    Serial.println(F("AUV provisioning tool. Commands: STATUS, PROVISION, BOOTTEST"));
    status();
}

void loop() {
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\r') continue;
        if (c != '\n') { if (line.length() < 32) line += c; continue; }
        line.trim();
        if (line == "STATUS") status();
        else if (line == "PROVISION") {
            AUV_Status s = nm.provision(flash, 1);
            Serial.print(F("Provision: ")); Serial.print(AUV_statusName(s));
            Serial.print(F("  epoch now ")); Serial.println(nm.epoch());
        } else if (line == "BOOTTEST") {
            uint32_t before = nm.inspect(flash);
            AUV_Status s = nm.begin(flash);
            Serial.print(F("Boot: ")); Serial.print(AUV_statusName(s));
            Serial.print(F("  ")); Serial.print(before); Serial.print(F(" -> ")); Serial.println(nm.epoch());
        } else if (line.length()) Serial.println(F("Unknown command"));
        line = "";
    }
}
