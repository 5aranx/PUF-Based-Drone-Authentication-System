/*
 * auth_client.c – HTTP challenge-response authentication using esp_http_client
 *                 and mbedTLS HMAC-SHA256.
 *
 * JSON parsing is done with simple string searches to avoid pulling in a
 * JSON library.  The server responses are small and well-known in structure.
 *
 * Compile-time guard: on host (non-IDF) the ESP-IDF specific includes are
 * replaced by stubs so the file can be syntax-checked with plain gcc.
 */

#include "auth_client.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef CONFIG_IDF_TARGET
/* ---- ESP-IDF includes --------------------------------------------------- */
#include "esp_http_client.h"
#include "esp_log.h"
#include "mbedtls/md.h"
#include "esp_timer.h"   /* esp_timer_get_time() → microseconds */
#else
/* ---- Host stub types (syntax-check only) -------------------------------- */
typedef void* esp_http_client_handle_t;
typedef struct { const char *url; } esp_http_client_config_t;
static inline esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *c) { (void)c; return NULL; }
static inline int  esp_http_client_perform(esp_http_client_handle_t h)              { (void)h; return -1; }
static inline int  esp_http_client_get_status_code(esp_http_client_handle_t h)      { (void)h; return 0; }
static inline int  esp_http_client_read_response(esp_http_client_handle_t h, char *b, int l) { (void)h;(void)b;(void)l; return 0; }
static inline void esp_http_client_cleanup(esp_http_client_handle_t h)              { (void)h; }
static inline void esp_http_client_set_method(esp_http_client_handle_t h, int m)   { (void)h;(void)m; }
static inline void esp_http_client_set_header(esp_http_client_handle_t h, const char *k, const char *v) { (void)h;(void)k;(void)v; }
static inline void esp_http_client_set_post_field(esp_http_client_handle_t h, const char *d, int l)     { (void)h;(void)d;(void)l; }
#define HTTP_METHOD_GET  0
#define HTTP_METHOD_POST 1
#define ESP_OK 0
#define ESP_LOGE(tag, fmt, ...) ((void)0)
#define ESP_LOGI(tag, fmt, ...) ((void)0)
#define ESP_LOGW(tag, fmt, ...) ((void)0)
/* Minimal mbedTLS stubs */
#define MBEDTLS_MD_SHA256 6
typedef int mbedtls_md_type_t;
typedef struct mbedtls_md_info_t mbedtls_md_info_t;
typedef struct { int dummy; } mbedtls_md_context_t;
static inline const mbedtls_md_info_t* mbedtls_md_info_from_type(mbedtls_md_type_t t) { (void)t; return NULL; }
static inline void mbedtls_md_init(mbedtls_md_context_t *c)                     { (void)c; }
static inline int  mbedtls_md_setup(mbedtls_md_context_t *c,const void*i,int h) { (void)c;(void)i;(void)h; return 0; }
static inline int  mbedtls_md_hmac_starts(mbedtls_md_context_t *c,const unsigned char*k,size_t l) { (void)c;(void)k;(void)l; return 0; }
static inline int  mbedtls_md_hmac_update(mbedtls_md_context_t *c,const unsigned char*i,size_t l) { (void)c;(void)i;(void)l; return 0; }
static inline int  mbedtls_md_hmac_finish(mbedtls_md_context_t *c,unsigned char*o)               { (void)c;(void)o; return 0; }
static inline void mbedtls_md_free(mbedtls_md_context_t *c)                     { (void)c; }
static inline long long esp_timer_get_time(void) { return 0LL; }
#endif /* CONFIG_IDF_TARGET */

static const char *TAG = "auth_client";

#define RESP_BUF_SIZE  512
#define URL_BUF_SIZE   256
#define MAC_HEX_LEN    64   /* HMAC-SHA256 = 32 bytes = 64 hex chars */
#define NONCE_HEX_LEN  32   /* 16-byte nonce expressed as 32 hex chars */
#define POST_BUF_SIZE  256
#define TS_STR_LEN     20

/* =========================================================================
 * Minimal JSON string extractor
 *
 * Finds the value of "key":"value" in a JSON object.
 * Copies at most val_max-1 chars into val_out (null-terminated).
 * Returns 0 on success, -1 if the key is not found.
 * ========================================================================= */
static int json_get_string(const char *json, const char *key,
                            char *val_out, size_t val_max)
{
    /* Build search pattern: "key":" */
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);

    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += strlen(pattern);

    /* Copy until closing '"' */
    size_t i = 0;
    while (*p && *p != '"' && i < val_max - 1) {
        val_out[i++] = *p++;
    }
    val_out[i] = '\0';
    if (*p != '"') return -1; /* unterminated string */
    return 0;
}

/* =========================================================================
 * Bytes → lowercase hex string
 * ========================================================================= */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex_out[i * 2]     = hx[bytes[i] >> 4];
        hex_out[i * 2 + 1] = hx[bytes[i] & 0x0F];
    }
    hex_out[len * 2] = '\0';
}

/* =========================================================================
 * HTTP GET helper – performs a GET and reads the response body.
 * Returns HTTP status code, or -1 on transport error.
 * ========================================================================= */
static int http_get(const char *url, char *resp_buf, int resp_max)
{
#ifdef CONFIG_IDF_TARGET
    esp_http_client_config_t cfg = { .url = url };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) return -1;

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        esp_http_client_cleanup(client);
        return -1;
    }
    int status = esp_http_client_get_status_code(client);
    int len    = esp_http_client_read_response(client, resp_buf, resp_max - 1);
    if (len >= 0) resp_buf[len] = '\0';
    else          resp_buf[0]   = '\0';
    esp_http_client_cleanup(client);
    return status;
#else
    (void)url; (void)resp_buf; (void)resp_max;
    return -1;
#endif
}

/* =========================================================================
 * HTTP POST helper – sends a JSON body and reads the response body.
 * Returns HTTP status code, or -1 on transport error.
 * ========================================================================= */
static int http_post_json(const char *url,
                           const char *body,
                           char *resp_buf, int resp_max)
{
#ifdef CONFIG_IDF_TARGET
    esp_http_client_config_t cfg = { .url = url };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) return -1;

    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, (int)strlen(body));

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        esp_http_client_cleanup(client);
        return -1;
    }
    int status = esp_http_client_get_status_code(client);
    int len    = esp_http_client_read_response(client, resp_buf, resp_max - 1);
    if (len >= 0) resp_buf[len] = '\0';
    else          resp_buf[0]   = '\0';
    esp_http_client_cleanup(client);
    return status;
#else
    (void)url; (void)body; (void)resp_buf; (void)resp_max;
    return -1;
#endif
}

/* =========================================================================
 * auth_run – full challenge-response authentication
 * ========================================================================= */
auth_result_t auth_run(const char *device_id,
                        const uint8_t *key,
                        const char *server_url,
                        char *token_out,
                        size_t token_len)
{
    char resp_buf[RESP_BUF_SIZE];
    char url_buf[URL_BUF_SIZE];
    char nonce_hex[NONCE_HEX_LEN + 1];
    char ts_str[TS_STR_LEN];
    char post_body[POST_BUF_SIZE];
    uint8_t mac_bytes[32];
    char mac_hex[MAC_HEX_LEN + 1];

    /* ------------------------------------------------------------------
     * Step 1: GET /challenge?device_id=<id>
     * ------------------------------------------------------------------ */
    snprintf(url_buf, sizeof(url_buf),
             "%s/challenge?device_id=%s", server_url, device_id);

    ESP_LOGI(TAG, "GET %s", url_buf);
    int status = http_get(url_buf, resp_buf, sizeof(resp_buf));
    if (status != 200) {
        ESP_LOGE(TAG, "GET /challenge failed, status=%d", status);
        return AUTH_NET_FAIL;
    }

    /* Parse nonce from {"nonce":"<hex>"} */
    if (json_get_string(resp_buf, "nonce", nonce_hex, sizeof(nonce_hex)) != 0) {
        ESP_LOGE(TAG, "Could not parse nonce from: %s", resp_buf);
        return AUTH_NONCE_FAIL;
    }
    nonce_hex[NONCE_HEX_LEN] = '\0'; /* ensure NUL-terminated */

    /* ------------------------------------------------------------------
     * Step 2: Compute HMAC-SHA256(key, "<device_id>|<nonce>|<ts>")
     * ------------------------------------------------------------------ */
#ifdef CONFIG_IDF_TARGET
    long long us = esp_timer_get_time();
    long long ts_sec = us / 1000000LL;
#else
    long long ts_sec = 0LL;
#endif
    snprintf(ts_str, sizeof(ts_str), "%lld", ts_sec);

    /* message = device_id + "|" + nonce_hex + "|" + ts_str */
    char msg_buf[256];
    int msg_len = snprintf(msg_buf, sizeof(msg_buf),
                           "%s|%s|%s", device_id, nonce_hex, ts_str);
    if (msg_len < 0 || msg_len >= (int)sizeof(msg_buf)) {
        ESP_LOGE(TAG, "Message buffer overflow");
        return AUTH_HMAC_FAIL;
    }

    mbedtls_md_context_t hmac_ctx;
    mbedtls_md_init(&hmac_ctx);
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int rc = mbedtls_md_setup(&hmac_ctx, md_info, /*hmac=*/1);
    if (rc != 0) {
        mbedtls_md_free(&hmac_ctx);
        ESP_LOGE(TAG, "mbedtls_md_setup failed: %d", rc);
        return AUTH_HMAC_FAIL;
    }
    rc  = mbedtls_md_hmac_starts(&hmac_ctx, key, 16);
    rc |= mbedtls_md_hmac_update(&hmac_ctx,
                                  (const unsigned char *)msg_buf,
                                  (size_t)msg_len);
    rc |= mbedtls_md_hmac_finish(&hmac_ctx, mac_bytes);
    mbedtls_md_free(&hmac_ctx);

    if (rc != 0) {
        ESP_LOGE(TAG, "HMAC computation failed: %d", rc);
        return AUTH_HMAC_FAIL;
    }
    bytes_to_hex(mac_bytes, sizeof(mac_bytes), mac_hex);

    /* ------------------------------------------------------------------
     * Step 3: POST /verify {"device_id":...,"nonce":...,"ts":...,"mac":...}
     * ------------------------------------------------------------------ */
    snprintf(url_buf, sizeof(url_buf), "%s/verify", server_url);

    int body_len = snprintf(post_body, sizeof(post_body),
        "{\"device_id\":\"%s\",\"nonce\":\"%s\",\"ts\":\"%s\",\"mac\":\"%s\"}",
        device_id, nonce_hex, ts_str, mac_hex);
    if (body_len < 0 || body_len >= (int)sizeof(post_body)) {
        ESP_LOGE(TAG, "POST body overflow");
        return AUTH_NET_FAIL;
    }

    ESP_LOGI(TAG, "POST %s", url_buf);
    status = http_post_json(url_buf, post_body, resp_buf, sizeof(resp_buf));

    /* Zeroize sensitive local data */
    memset(mac_bytes, 0, sizeof(mac_bytes));
    memset(msg_buf, 0, sizeof(msg_buf));

    if (status != 200) {
        ESP_LOGE(TAG, "POST /verify failed, status=%d, body=%s",
                 status, resp_buf);
        return AUTH_REJECT;
    }

    /* Parse token from {"token":"<JWT>"} */
    if (json_get_string(resp_buf, "token", token_out, token_len) != 0) {
        ESP_LOGE(TAG, "Could not parse token from: %s", resp_buf);
        return AUTH_REJECT;
    }

    ESP_LOGI(TAG, "Authentication successful, token length=%d",
             (int)strlen(token_out));
    return AUTH_OK;
}
