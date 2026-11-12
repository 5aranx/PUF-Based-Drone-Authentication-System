#pragma once
/*
 * auth_client.h – PUF drone HMAC-based authentication client
 *
 * Protocol (HTTP, two-step challenge-response):
 *
 *   1. GET  /challenge?device_id=<id>
 *           ← {"nonce":"<32-hex-chars>"}
 *
 *   2. Build message:  msg = "<device_id>|<nonce_hex>|<unix_timestamp>"
 *      Compute:        mac = HMAC-SHA256(key, msg)  → 32 bytes → 64 hex chars
 *
 *   3. POST /verify
 *          {"device_id":"<id>","nonce":"<nonce_hex>","ts":"<timestamp>","mac":"<mac_hex>"}
 *          ← {"token":"<JWT>"}
 *
 * On success the JWT is copied into token_out (up to token_len bytes).
 */

#include <stdint.h>
#include <stddef.h>

typedef enum {
    AUTH_OK         = 0,  /* success, token_out is valid */
    AUTH_NET_FAIL   = 1,  /* TCP/HTTP connection or send/recv error */
    AUTH_NONCE_FAIL = 2,  /* could not parse nonce from /challenge response */
    AUTH_HMAC_FAIL  = 3,  /* HMAC computation error (mbedTLS failure) */
    AUTH_REJECT     = 4,  /* server rejected the MAC (wrong key or replay) */
} auth_result_t;

/*
 * Run a full challenge-response authentication against the server.
 *
 *   device_id  – null-terminated device identifier string
 *   key        – 16-byte HMAC key (derived from PUF)
 *   server_url – base URL, e.g. "http://192.168.1.100:5000" (no trailing slash)
 *   token_out  – output buffer for the returned JWT
 *   token_len  – size of token_out in bytes (256 recommended)
 *
 * Returns AUTH_OK on success; a non-zero auth_result_t on failure.
 * The key buffer is NOT zeroed here; callers must zeroise it after use.
 */
auth_result_t auth_run(const char *device_id,
                       const uint8_t *key,
                       const char *server_url,
                       char *token_out,
                       size_t token_len);
