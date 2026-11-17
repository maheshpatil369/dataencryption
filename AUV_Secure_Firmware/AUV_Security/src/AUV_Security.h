/*
 * AUV_Security.h  -  single include for the whole library
 *
 *   #include <AUV_Security.h>
 *
 * Requires the "Crypto" library by Rhys Weatherley (Arduino Library Manager).
 */
#ifndef AUV_SECURITY_H
#define AUV_SECURITY_H

#include "AUV_SecurityConfig.h"
#include "AUV_Packet.h"
#include "AUV_KeyManager.h"
#include "AUV_NonceManager.h"
#include "AUV_ReplayProtection.h"
#include "AUV_Encrypt.h"
#include "AUV_Decrypt.h"
#include "AUV_SecureLink.h"
#include "AUV_NodeProtocol.h"
#include "AUV_Platform.h"

#define AUV_SECURITY_LIB_VERSION "1.0.0"

#endif
