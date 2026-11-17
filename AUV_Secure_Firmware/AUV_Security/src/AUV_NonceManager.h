/*
 * AUV_NonceManager.h
 * ---------------------------------------------------------------------------
 * Guarantees that an AES-GCM nonce is NEVER reused with the same key, even
 * across power loss, brown-out, watchdog reset and firmware re-flashing.
 *
 * Nonce = boot_epoch(32) || packet_counter(32) || src || dst || 0 || 0
 *
 *  - boot_epoch is stored in flash and increased by one on EVERY boot,
 *    BEFORE the first packet is encrypted. The write is read back and
 *    verified; if it cannot be verified the device refuses to transmit.
 *  - packet_counter lives in RAM per link and only goes up. When it reaches
 *    AUV_COUNTER_LIMIT the link stops transmitting (reboot = new epoch).
 *  - We never write flash at 100 Hz: one small record per boot.
 *
 * Power-loss safe storage (append-only log over two flash pages):
 *  - Each record is 16 bytes: magic | epoch | ~epoch | CRC32.
 *  - New records are appended into blank slots. A page is erased only when
 *    the other page is full, and the erased page never holds the newest
 *    record. So a power cut during erase or programming can only destroy the
 *    record being written - whose epoch has not been used yet.
 *  - On boot the highest valid epoch in either page is taken.
 *  - If NO valid record exists (blank or corrupt flash) the device LOCKS and
 *    will not transmit. It never silently restarts at epoch 1, because that
 *    would reuse old nonces with the same keys. Run the AUV_Provision sketch
 *    (see docs) to initialise storage.
 *
 * Flash wear: 1KB page = 64 records, two pages alternate, so ~1.28 million
 * boots for 10k-cycle flash.
 *
 * Backends:
 *  - AUV_STM32F1Flash   : STM32F1 (Blue Pill) via HAL, two dedicated pages
 *  - AUV_STM32EepromFlash: other STM32 families via STM32duino EEPROM
 *                          emulation (single sector; a power cut during its
 *                          flush leaves storage invalid -> device LOCKS, safe
 *                          but needs re-provisioning)
 *  - AUV_RamFlash       : RAM simulation with power-failure injection, used
 *                          by the self-test and host tests
 * ---------------------------------------------------------------------------
 */
#ifndef AUV_NONCE_MANAGER_H
#define AUV_NONCE_MANAGER_H

#include <string.h>
#include "AUV_SecurityConfig.h"
#include "AUV_Packet.h"

#define AUV_NVM_RECORD_SIZE  16
#define AUV_NVM_MAGIC        0x31455541UL   /* "AUE1" little-endian */

/* --------------------------- CRC32 (IEEE) -------------------------------- */
inline uint32_t AUV_crc32(const uint8_t *d, size_t n) {
    uint32_t c = 0xFFFFFFFFUL;
    while (n--) {
        c ^= *d++;
        for (uint8_t k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320UL & (0U - (c & 1U)));
    }
    return ~c;
}

/* ----------------------- flash backend interface ------------------------- */
class AUV_FlashBackend {
public:
    virtual ~AUV_FlashBackend() {}
    virtual uint32_t pageSize() const = 0;                       /* bytes, multiple of 16 */
    virtual bool read(uint8_t page, uint32_t off, uint8_t *buf, uint32_t len) = 0;
    virtual bool erase(uint8_t page) = 0;                        /* -> all 0xFF */
    virtual bool program(uint8_t page, uint32_t off, const uint8_t *data, uint32_t len) = 0;
    virtual AUV_Status checkLayout() { return AUV_OK; }
};

/* ---------------------- RAM simulation (tests) --------------------------- */
#ifndef AUV_RAMFLASH_PAGE_SIZE
#define AUV_RAMFLASH_PAGE_SIZE 256
#endif
class AUV_RamFlash : public AUV_FlashBackend {
public:
    AUV_RamFlash() : failProgramAfter(-1), failEraseHalfway(false), eraseCount(0), programCount(0) {
        memset(mem, 0xFF, sizeof(mem));
    }
    uint32_t pageSize() const { return AUV_RAMFLASH_PAGE_SIZE; }
    bool read(uint8_t page, uint32_t off, uint8_t *buf, uint32_t len) {
        if (page > 1 || off + len > AUV_RAMFLASH_PAGE_SIZE) return false;
        memcpy(buf, mem[page] + off, len);
        return true;
    }
    bool erase(uint8_t page) {
        if (page > 1) return false;
        eraseCount++;
        if (failEraseHalfway) {           /* simulate power cut mid-erase */
            failEraseHalfway = false;
            memset(mem[page], 0xFF, AUV_RAMFLASH_PAGE_SIZE / 2);
            mem[page][AUV_RAMFLASH_PAGE_SIZE / 2] ^= 0x5A;
            return false;
        }
        memset(mem[page], 0xFF, AUV_RAMFLASH_PAGE_SIZE);
        return true;
    }
    bool program(uint8_t page, uint32_t off, const uint8_t *data, uint32_t len) {
        if (page > 1 || off + len > AUV_RAMFLASH_PAGE_SIZE) return false;
        programCount++;
        for (uint32_t i = 0; i < len; i++) {
            if (failProgramAfter == 0) { failProgramAfter = -1; return false; } /* power cut */
            if (failProgramAfter > 0) failProgramAfter--;
            if (mem[page][off + i] != 0xFF) return false;     /* like real flash: no overwrite */
            mem[page][off + i] = data[i];
        }
        return true;
    }
    void wipe() { memset(mem, 0xFF, sizeof(mem)); }
    uint8_t mem[2][AUV_RAMFLASH_PAGE_SIZE];
    int32_t failProgramAfter;    /* bytes before simulated power cut, -1 = never */
    bool    failEraseHalfway;
    uint32_t eraseCount, programCount;
};

/* ---------------------- STM32F1 (Blue Pill) backend ---------------------- */
#if defined(ARDUINO_ARCH_STM32) && defined(STM32F1xx)
#include <Arduino.h>
extern "C" {
    extern uint32_t _sidata;   /* from STM32duino linker script */
    extern uint32_t _sdata;
    extern uint32_t _edata;
}
class AUV_STM32F1Flash : public AUV_FlashBackend {
public:
    /* Default: the 3rd and 2nd last pages of the flash reported by the chip.
     * The very last page is left for STM32duino's EEPROM library. */
    AUV_STM32F1Flash(uint32_t pageA = 0, uint32_t pageB = 0) {
        uint32_t flashBytes = (uint32_t)(*(const uint16_t *)FLASHSIZE_BASE) * 1024UL;
        uint32_t end = FLASH_BASE + flashBytes;
        _addr[0] = pageA ? pageA : end - 3UL * FLASH_PAGE_SIZE;
        _addr[1] = pageB ? pageB : end - 2UL * FLASH_PAGE_SIZE;
    }
    uint32_t pageSize() const { return FLASH_PAGE_SIZE; }
    bool read(uint8_t page, uint32_t off, uint8_t *buf, uint32_t len) {
        if (page > 1 || off + len > FLASH_PAGE_SIZE) return false;
        memcpy(buf, (const void *)(_addr[page] + off), len);
        return true;
    }
    bool erase(uint8_t page) {
        if (page > 1) return false;
        FLASH_EraseInitTypeDef e;
        memset(&e, 0, sizeof(e));
        e.TypeErase = FLASH_TYPEERASE_PAGES;
        e.Banks = FLASH_BANK_1;
        e.PageAddress = _addr[page];
        e.NbPages = 1;
        uint32_t pageErr = 0;
        HAL_FLASH_Unlock();
        __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_PGERR | FLASH_FLAG_WRPERR);
        HAL_StatusTypeDef st = HAL_FLASHEx_Erase(&e, &pageErr);
        HAL_FLASH_Lock();
        return st == HAL_OK && pageErr == 0xFFFFFFFFUL;
    }
    bool program(uint8_t page, uint32_t off, const uint8_t *data, uint32_t len) {
        if (page > 1 || off + len > FLASH_PAGE_SIZE || (off & 1U) || (len & 1U)) return false;
        bool ok = true;
        HAL_FLASH_Unlock();
        __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_PGERR | FLASH_FLAG_WRPERR);
        for (uint32_t i = 0; i < len && ok; i += 2) {
            uint16_t hw = (uint16_t)(data[i] | (data[i + 1] << 8));
            ok = HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD, _addr[page] + off + i, hw) == HAL_OK;
        }
        HAL_FLASH_Lock();
        return ok;
    }
    AUV_Status checkLayout() {
        uint32_t imageEnd = (uint32_t)&_sidata + ((uint32_t)&_edata - (uint32_t)&_sdata);
        uint32_t lo = _addr[0] < _addr[1] ? _addr[0] : _addr[1];
        if (imageEnd > lo) return AUV_ERR_NVM_OVERLAP;     /* sketch grew into the log */
        if ((_addr[0] % FLASH_PAGE_SIZE) || (_addr[1] % FLASH_PAGE_SIZE) || _addr[0] == _addr[1])
            return AUV_ERR_NVM_OVERLAP;
        return AUV_OK;
    }
    uint32_t pageAddress(uint8_t p) const { return _addr[p & 1]; }
private:
    uint32_t _addr[2];
};
#define AUV_HAS_DEFAULT_FLASH 1
typedef AUV_STM32F1Flash AUV_DefaultFlash;

/* ---------------- other STM32 families: EEPROM emulation ----------------- */
#elif defined(ARDUINO_ARCH_STM32) && !defined(DATA_EEPROM_BASE)
#include <Arduino.h>
#include <EEPROM.h>
#ifndef AUV_EEPROM_LOG_OFFSET
#define AUV_EEPROM_LOG_OFFSET 0
#endif
#define AUV_EEPROM_PAGE 256
class AUV_STM32EepromFlash : public AUV_FlashBackend {
public:
    AUV_STM32EepromFlash() : _filled(false) {}
    uint32_t pageSize() const { return AUV_EEPROM_PAGE; }
    bool read(uint8_t page, uint32_t off, uint8_t *buf, uint32_t len) {
        if (page > 1 || off + len > AUV_EEPROM_PAGE) return false;
        fill();
        for (uint32_t i = 0; i < len; i++)
            buf[i] = eeprom_buffered_read_byte(base(page) + off + i);
        return true;
    }
    bool erase(uint8_t page) {
        if (page > 1) return false;
        fill();
        for (uint32_t i = 0; i < AUV_EEPROM_PAGE; i++) eeprom_buffered_write_byte(base(page) + i, 0xFF);
        eeprom_buffer_flush();
        return true;
    }
    bool program(uint8_t page, uint32_t off, const uint8_t *data, uint32_t len) {
        if (page > 1 || off + len > AUV_EEPROM_PAGE) return false;
        fill();
        for (uint32_t i = 0; i < len; i++) eeprom_buffered_write_byte(base(page) + off + i, data[i]);
        eeprom_buffer_flush();
        _filled = false;                    /* force re-read from flash to verify */
        return true;
    }
    AUV_Status checkLayout() {
        return (AUV_EEPROM_LOG_OFFSET + 2UL * AUV_EEPROM_PAGE <= (uint32_t)E2END + 1UL) ? AUV_OK : AUV_ERR_NVM_OVERLAP;
    }
private:
    uint32_t base(uint8_t page) const { return AUV_EEPROM_LOG_OFFSET + (uint32_t)page * AUV_EEPROM_PAGE; }
    void fill() { if (!_filled) { eeprom_buffer_fill(); _filled = true; } }
    bool _filled;
};
#define AUV_HAS_DEFAULT_FLASH 1
typedef AUV_STM32EepromFlash AUV_DefaultFlash;
#endif

/* --------------------------- nonce manager ------------------------------- */
class AUV_NonceManager {
public:
    AUV_NonceManager() : _flash(0), _epoch(0), _status(AUV_ERR_NOT_READY),
                         _activePage(0), _nextSlot(0), _lastValid(0), _suspect(false), _damageAtBoot(false) {}

    /* Call ONCE in setup(), before starting FreeRTOS / before any link
     * transmits. Takes ~20-40 ms on F1 only when a page erase is needed
     * (once every 64 boots); otherwise one 16-byte program (<1 ms). */
    AUV_Status begin(AUV_FlashBackend &flash) {
        _flash = &flash;
        _epoch = 0;
        AUV_Status s = flash.checkLayout();
        if (s != AUV_OK) return fail(s);
        scan();
        if (_lastValid == 0) return fail(AUV_ERR_NVM_INVALID);
        /* If a damaged record sits AFTER the newest valid one, that damaged
         * record may have been the newest epoch and may already have been
         * used. Skip over it (+2) instead of risking reuse (+1). */
        _damageAtBoot = _suspect;
        uint32_t step = _suspect ? 2 : 1;
        if (_lastValid >= AUV_EPOCH_LIMIT - step) return fail(AUV_ERR_EPOCH_EXHAUSTED);
        return commit(_lastValid + step);
    }

    /* Provisioning: initialise blank/corrupt storage, or move the epoch
     * forward. NEVER moves it backwards. If storage is blank, the keys in use
     * MUST be freshly generated (never used before) - see docs. */
    AUV_Status provision(AUV_FlashBackend &flash, uint32_t minEpoch) {
        _flash = &flash;
        AUV_Status s = flash.checkLayout();
        if (s != AUV_OK) return fail(s);
        if (minEpoch == 0) minEpoch = 1;
        scan();
        _damageAtBoot = _suspect;
        uint32_t next = _lastValid + (_suspect ? 2 : 1);
        uint32_t target = (next > minEpoch) ? next : minEpoch;
        if (_lastValid == 0) {
            /* nothing valid: start from clean pages */
            if (!flash.erase(0) || !flash.erase(1)) return fail(AUV_ERR_NVM_WRITE);
            _activePage = 0;
            _nextSlot = 0;
        }
        return commit(target);
    }

    bool       ready()  const { return _status == AUV_OK && _epoch != 0; }
    uint32_t   epoch()  const { return _status == AUV_OK ? _epoch : 0; }
    AUV_Status status() const { return _status; }
    uint32_t   highestStoredEpoch() const { return _lastValid; }
    /* true if this boot found a damaged record newer than the newest valid
     * one and therefore skipped an epoch (report it: flash may be failing) */
    bool       damagedRecordFound() const { return _damageAtBoot; }

    /* Read-only inspection used by the provisioning sketch */
    uint32_t inspect(AUV_FlashBackend &flash) { _flash = &flash; scan(); return _lastValid; }

private:
    AUV_Status fail(AUV_Status s) { _status = s; _epoch = 0; return s; }

    static void makeRecord(uint32_t epoch, uint8_t r[AUV_NVM_RECORD_SIZE]) {
        AUV_putU32(r, AUV_NVM_MAGIC);
        AUV_putU32(r + 4, epoch);
        AUV_putU32(r + 8, ~epoch);
        AUV_putU32(r + 12, AUV_crc32(r, 12));
    }
    static bool parseRecord(const uint8_t r[AUV_NVM_RECORD_SIZE], uint32_t &epoch) {
        if (AUV_getU32(r) != AUV_NVM_MAGIC) return false;
        uint32_t e = AUV_getU32(r + 4);
        if (AUV_getU32(r + 8) != ~e) return false;
        if (AUV_getU32(r + 12) != AUV_crc32(r, 12)) return false;
        if (e == 0 || e > AUV_EPOCH_LIMIT) return false;
        epoch = e;
        return true;
    }
    static bool isBlank(const uint8_t r[AUV_NVM_RECORD_SIZE]) {
        for (uint8_t i = 0; i < AUV_NVM_RECORD_SIZE; i++) if (r[i] != 0xFF) return false;
        return true;
    }

    /* Find highest valid epoch, which page holds it and the first slot after
     * the last used (non-blank) slot of that page. */
    void scan() {
        uint32_t slots = _flash->pageSize() / AUV_NVM_RECORD_SIZE;
        uint8_t r[AUV_NVM_RECORD_SIZE];
        _lastValid = 0;
        _activePage = 0;
        _suspect = false;
        uint32_t lastUsed[2] = {0, 0};
        uint32_t maxSlot = 0;
        bool any[2] = {false, false};
        /* first pass: newest valid record */
        for (uint8_t p = 0; p < 2; p++) {
            for (uint32_t s = 0; s < slots; s++) {
                if (!_flash->read(p, s * AUV_NVM_RECORD_SIZE, r, sizeof(r))) continue;
                if (isBlank(r)) continue;
                any[p] = true;
                lastUsed[p] = s;
                uint32_t e;
                if (parseRecord(r, e) && e > _lastValid) { _lastValid = e; _activePage = p; maxSlot = s; }
            }
        }
        /* second pass: damaged (non-blank, invalid) records that could be
         * newer than the newest valid one */
        for (uint8_t p = 0; p < 2 && _lastValid; p++) {
            for (uint32_t s = 0; s < slots; s++) {
                if (p == _activePage && s <= maxSlot) continue;
                if (!_flash->read(p, s * AUV_NVM_RECORD_SIZE, r, sizeof(r))) continue;
                uint32_t e;
                if (!isBlank(r) && !parseRecord(r, e)) { _suspect = true; break; }
            }
        }
        _nextSlot = any[_activePage] ? lastUsed[_activePage] + 1 : 0;
    }

    /* Write a record for 'epoch' and verify it. Up to 3 attempts, each in a
     * fresh slot, so a single bad half-word cannot lock the device. */
    AUV_Status commit(uint32_t epoch) {
        uint32_t slots = _flash->pageSize() / AUV_NVM_RECORD_SIZE;
        uint8_t rec[AUV_NVM_RECORD_SIZE], back[AUV_NVM_RECORD_SIZE];
        makeRecord(epoch, rec);
        for (uint8_t attempt = 0; attempt < 3; attempt++) {
            if (_nextSlot >= slots) {
                uint8_t other = (uint8_t)(_activePage ^ 1);
                if (!_flash->erase(other)) { _nextSlot = slots; continue; }
                _activePage = other;
                _nextSlot = 0;
            }
            uint32_t off = _nextSlot * AUV_NVM_RECORD_SIZE;
            _nextSlot++;
            if (!_flash->program(_activePage, off, rec, sizeof(rec))) continue;
            uint32_t got = 0;
            if (!_flash->read(_activePage, off, back, sizeof(back))) continue;
            if (!parseRecord(back, got) || got != epoch) continue;
            /* Final check: a full rescan must now report this epoch. */
            scan();
            if (_lastValid != epoch) continue;
            _epoch = epoch;
            _status = AUV_OK;
            return AUV_OK;
        }
        return fail(AUV_ERR_NVM_WRITE);
    }

    AUV_FlashBackend *_flash;
    uint32_t   _epoch;
    AUV_Status _status;
    uint8_t    _activePage;
    uint32_t   _nextSlot;
    uint32_t   _lastValid;
    bool       _suspect;
    bool       _damageAtBoot;
};

/* Per-link transmit counter. Strictly increasing, never wraps. */
class AUV_TxSequence {
public:
    AUV_TxSequence() : _next(0) {}
    void reset() { _next = 0; }          /* only valid together with a NEW epoch */
    bool take(uint32_t &out) {
        if (_next >= AUV_COUNTER_LIMIT) return false;
        out = _next++;
        return true;
    }
    uint32_t peek() const { return _next; }
    /* test hook: jump close to the limit to test exhaustion */
    void testSet(uint32_t v) { _next = v; }
private:
    uint32_t _next;
};

#endif /* AUV_NONCE_MANAGER_H */
