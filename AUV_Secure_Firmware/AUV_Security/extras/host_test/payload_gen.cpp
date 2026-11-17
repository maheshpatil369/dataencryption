// Emits C++-encoded payloads (hex) so the Python decoders can be checked.
#include <AUV_Security.h>
#include <cstdio>
static void hex(const char *n, const uint8_t *p, int len) { printf("%s ", n); for (int i = 0; i < len; i++) printf("%02x", p[i]); printf("\n"); }
int main() {
    AUV_SensorTelemetry s = {}; s.tick = 1234; s.voltage = 12.5f; s.current = 1.25f; s.power = 15.625f;
    s.temperature = 24.5f; s.humidity = 55.0f; s.leakMask = 0x05; s.relay = 1; s.leakActive = 1; s.flags = 3;
    uint8_t sp[AUV_SENSOR_TELEM_LEN]; AUV_encodeSensorTelemetry(s, sp); hex("SENSOR", sp, sizeof sp);
    AUV_ImuTelemetry m = {}; m.tick = 99; m.q[3] = 1.0f; m.accel[2] = 9.75f; m.gyro[0] = 0.5f; m.mag[1] = -20.0f; m.connected = 1;
    uint8_t ip[AUV_IMU_TELEM_LEN]; AUV_encodeImuTelemetry(m, ip); hex("IMU", ip, sizeof ip);
    AUV_ThrusterStatus t = {{10, 20, 30, 40}, 1700, 1, 1, THR_STATE_ACTIVE, 0, 7};
    uint8_t tp[AUV_THRUSTER_STATUS_LEN]; AUV_encodeThrusterStatus(t, tp); hex("THRUSTER", tp, sizeof tp);
    uint8_t env[AUV_MAX_PAYLOAD]; uint8_t el = AUV_encodeEnvelope(AUV_ID_IMU, 5, 77, ip, sizeof ip, env); hex("ENV", env, el);
    AUV_ThrusterCmd c; return 0 * AUV_decodeThrusterCmd(sp, 8, c);
}
