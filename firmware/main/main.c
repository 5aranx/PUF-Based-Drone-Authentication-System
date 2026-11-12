/*
 * main.c – PUF-based drone authentication firmware for ESP32
 *
 * State machine:
 *
 *   STATE_BOOT
 *     └─► (enrolled?)
 *           No  → STATE_PUF_ENROLL  (accumulate votes, restart until done,
 *                                    then generate key, enroll, save H+mask)
 *           Yes → STATE_PUF_READ
 *
 *   STATE_PUF_READ
 *     └─► Read SRAM PUF, apply mask, reconstruct K via fuzzy extractor
 *           Fail → STATE_DENY
 *           OK   → STATE_NET_CONNECT
 *
 *   STATE_NET_CONNECT
 *     └─► Connect WiFi
 *           Fail → STATE_DENY
 *           OK   → STATE_AUTH
 *
 *   STATE_AUTH
 *     └─► auth_run()
 *           Fail ×5 → STATE_LOCKOUT
 *           OK      → STATE_LIVE
 *
 *   STATE_LIVE
 *     └─► Publish MQTT telemetry every 100 ms
 *           Token expiry → STATE_AUTH
 *
 *   STATE_DENY    – log error, hold motors low, halt
 *   STATE_LOCKOUT – log, halt indefinitely
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifdef CONFIG_IDF_TARGET
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/gpio.h"
#include "mqtt_client.h"
#else
/* Host stubs for syntax check */
#define ESP_LOGI(tag, fmt, ...)   printf("[I][%s] " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGE(tag, fmt, ...)   printf("[E][%s] " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...)   printf("[W][%s] " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_ERROR_CHECK(x)        (void)(x)
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
typedef unsigned int uint32_t;
/* nvs stubs */
typedef int nvs_handle_t;
#define NVS_READWRITE 2
static inline esp_err_t nvs_flash_init(void) { return 0; }
static inline esp_err_t nvs_open(const char*n,int m,nvs_handle_t*h){(void)n;(void)m;*h=0;return 0;}
static inline esp_err_t nvs_get_u8(nvs_handle_t h,const char*k,uint8_t*v){(void)h;(void)k;*v=0;return 0;}
static inline esp_err_t nvs_set_u8(nvs_handle_t h,const char*k,uint8_t v){(void)h;(void)k;(void)v;return 0;}
static inline esp_err_t nvs_get_blob(nvs_handle_t h,const char*k,void*v,size_t*l){(void)h;(void)k;(void)v;(void)l;return 0;}
static inline esp_err_t nvs_set_blob(nvs_handle_t h,const char*k,const void*v,size_t l){(void)h;(void)k;(void)v;(void)l;return 0;}
static inline esp_err_t nvs_commit(nvs_handle_t h){(void)h;return 0;}
static inline void nvs_close(nvs_handle_t h){(void)h;}
static inline void esp_restart(void) {}
static inline uint32_t esp_random(void) { return 0; }
static inline long long esp_timer_get_time(void) { return 0; }
#define RTC_NOINIT_ATTR
#define GPIO_NUM_4  4
#define GPIO_MODE_OUTPUT 2
typedef int gpio_num_t;
typedef int gpio_mode_t;
static inline void gpio_set_direction(gpio_num_t g, gpio_mode_t m){(void)g;(void)m;}
static inline void gpio_set_level(gpio_num_t g, int l){(void)g;(void)l;}
static inline void vTaskDelay(int ms){(void)ms;}
#define pdMS_TO_TICKS(x) (x)
/* mqtt stubs */
typedef void *esp_mqtt_client_handle_t;
typedef struct { const char *broker_uri; } esp_mqtt_client_config_t;
static inline esp_mqtt_client_handle_t esp_mqtt_client_init(const esp_mqtt_client_config_t*c){(void)c;return NULL;}
static inline void esp_mqtt_client_start(esp_mqtt_client_handle_t h){(void)h;}
static inline int esp_mqtt_client_publish(esp_mqtt_client_handle_t h,const char*t,const char*d,int l,int q,int r){(void)h;(void)t;(void)d;(void)l;(void)q;(void)r;return 0;}
/* wifi stubs */
static inline void esp_netif_init(void){}
static inline void esp_event_loop_create_default(void){}
static inline void esp_netif_create_default_wifi_sta(void){}
typedef struct{int mode;}wifi_init_config_t;
#define WIFI_INIT_CONFIG_DEFAULT() {0}
static inline void esp_wifi_init(const wifi_init_config_t*c){(void)c;}
static inline void esp_wifi_set_mode(int m){(void)m;}
#define WIFI_MODE_STA 1
typedef struct{struct{char ssid[32];char password[64];}sta;}wifi_config_t;
static inline void esp_wifi_set_config(int i,wifi_config_t*c){(void)i;(void)c;}
#define WIFI_IF_STA 0
static inline void esp_wifi_start(void){}
#define CONFIG_DRONE_DEVICE_ID  "DRONE-001"
#define CONFIG_DRONE_SERVER_URL "http://192.168.1.100:5000"
#define CONFIG_DRONE_WIFI_SSID  "GCS_NET"
#define CONFIG_DRONE_WIFI_PASSWORD "changeme"
#define CONFIG_DRONE_WIFI_OPEN  0
#endif /* CONFIG_IDF_TARGET */

#include "puf.h"
#include "fuzzy_extractor.h"
#include "auth_client.h"

/* =========================================================================
 * Configuration & constants
 * ========================================================================= */
static const char *TAG = "puf_drone";

#define MOTOR_INHIBIT_GPIO   GPIO_NUM_4   /* Pull low to disable ESCs */
#define AUTH_MAX_RETRIES     5
#define TOKEN_LIFETIME_US    (3600LL * 1000000LL)  /* 1 hour in microseconds */
#define TELEMETRY_INTERVAL_MS 100
#define MQTT_BROKER_URI      "mqtt://192.168.1.100:1883"
#define NVS_NAMESPACE        "puf_drone"
#define NVS_KEY_ENROLLED     "enrolled"
#define NVS_KEY_HELPER       "helper_h"
#define NVS_KEY_MASK         "puf_mask"

/* =========================================================================
 * PUF vote state in RTC NOINIT memory (survives esp_restart)
 * ========================================================================= */
RTC_NOINIT_ATTR static puf_vote_state_t vote_state;

/* =========================================================================
 * State machine definition
 * ========================================================================= */
typedef enum {
    STATE_BOOT,
    STATE_PUF_ENROLL,
    STATE_PUF_READ,
    STATE_RECONSTRUCT,
    STATE_NET_CONNECT,
    STATE_AUTH,
    STATE_LIVE,
    STATE_DENY,
    STATE_LOCKOUT,
} drone_state_t;

/* =========================================================================
 * WiFi connection helper
 * ========================================================================= */
#ifdef CONFIG_IDF_TARGET

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
static EventGroupHandle_t s_wifi_event_group;
static int s_wifi_retry = 0;
#define WIFI_MAX_RETRY 10

static void wifi_event_handler(void *arg, esp_event_base_t base,
                                int32_t event_id, void *data)
{
    if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_wifi_retry < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_wifi_retry++;
            ESP_LOGW(TAG, "WiFi retry %d/%d", s_wifi_retry, WIFI_MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        s_wifi_retry = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}
#endif /* CONFIG_IDF_TARGET */

static esp_err_t wifi_connect(void)
{
#ifdef CONFIG_IDF_TARGET
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t inst_any, inst_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &inst_any));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &inst_got_ip));

    wifi_config_t wifi_cfg = {0};
    strncpy((char *)wifi_cfg.sta.ssid, CONFIG_DRONE_WIFI_SSID,
            sizeof(wifi_cfg.sta.ssid) - 1);
#if !CONFIG_DRONE_WIFI_OPEN
    strncpy((char *)wifi_cfg.sta.password, CONFIG_DRONE_WIFI_PASSWORD,
            sizeof(wifi_cfg.sta.password) - 1);
#endif

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to WiFi SSID: %s", CONFIG_DRONE_WIFI_SSID);

    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE,
        pdMS_TO_TICKS(30000));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connected");
        return ESP_OK;
    }
    ESP_LOGE(TAG, "WiFi connection failed");
    return ESP_FAIL;
#else
    return ESP_FAIL; /* host stub */
#endif
}

/* =========================================================================
 * NVS helpers
 * ========================================================================= */
static esp_err_t nvs_load_blob(const char *key, void *buf, size_t len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    size_t actual = len;
    err = nvs_get_blob(h, key, buf, &actual);
    nvs_close(h);
    return err;
}

static esp_err_t nvs_save_blob(const char *key, const void *buf, size_t len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, key, buf, len);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

static uint8_t nvs_get_enrolled(void)
{
    nvs_handle_t h;
    uint8_t val = 0;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_get_u8(h, NVS_KEY_ENROLLED, &val);
        nvs_close(h);
    }
    return val;
}

static void nvs_set_enrolled(uint8_t val)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, NVS_KEY_ENROLLED, val);
        nvs_commit(h);
        nvs_close(h);
    }
}

/* =========================================================================
 * Inhibit motors (pull GPIO low, make safe)
 * ========================================================================= */
static void inhibit_motors(void)
{
    gpio_set_direction(MOTOR_INHIBIT_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(MOTOR_INHIBIT_GPIO, 0);
    ESP_LOGI(TAG, "Motors inhibited (GPIO%d → LOW)", MOTOR_INHIBIT_GPIO);
}

/* =========================================================================
 * Zeroize a buffer (safe, not elided by compiler)
 * ========================================================================= */
static void secure_zero(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    for (size_t i = 0; i < len; i++) p[i] = 0;
}

/* =========================================================================
 * MQTT telemetry
 * ========================================================================= */
static esp_mqtt_client_handle_t mqtt_client = NULL;

static void mqtt_init(void)
{
#ifdef CONFIG_IDF_TARGET
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = MQTT_BROKER_URI,
    };
    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_start(mqtt_client);
    ESP_LOGI(TAG, "MQTT client started: %s", MQTT_BROKER_URI);
#endif
}

static void publish_telemetry(const char *device_id,
                               const char *token,
                               long long ts_us)
{
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"device_id\":\"%s\",\"ts\":%lld,\"status\":\"LIVE\","
             "\"token_prefix\":\"%.8s\"}",
             device_id, ts_us / 1000000LL, token);

    if (mqtt_client) {
        esp_mqtt_client_publish(mqtt_client,
                                "drone/telemetry", payload,
                                (int)strlen(payload), 1, 0);
    }
}

/* =========================================================================
 * Enrollment procedure
 *
 * Called when NVS "enrolled" == 0.
 * Uses vote_state (in RTC NOINIT) to accumulate PUF readings across
 * PUF_N_VOTES power cycles, then generates a random key K, enrolls,
 * and stores helper data + mask in NVS.
 * ========================================================================= */
static void run_enrollment(void)
{
    uint8_t raw[PUF_RAW_BYTES];
    puf_read_raw(raw, sizeof(raw));

    vote_state.boot_count++;
    puf_accumulate_votes(&vote_state, raw, sizeof(raw));

    ESP_LOGI(TAG, "Enrollment boot %lu/%d",
             (unsigned long)vote_state.boot_count, PUF_N_VOTES);

    if (vote_state.boot_count < PUF_N_VOTES) {
        /* Not done yet – restart to get another PUF sample */
        ESP_LOGI(TAG, "Restarting for next vote sample...");
        esp_restart();
        /* Not reached */
    }

    /* All votes accumulated – finalise */
    puf_finalise(&vote_state);
    ESP_LOGI(TAG, "PUF voting complete, finalised stable bits");

    /* Select 32 bytes (256 bits) of stable PUF bits; top bit is unused */
    uint8_t p_selected[PUF_SELECTED];
    puf_select_bits(vote_state.stable, vote_state.mask,
                    PUF_RAW_BYTES, p_selected, PUF_SELECTED);

    /* Generate a random 128-bit key */
    uint8_t key[16];
    for (int i = 0; i < 4; i++) {
        uint32_t rnd = esp_random();
        key[i * 4 + 0] = (uint8_t)(rnd >>  0);
        key[i * 4 + 1] = (uint8_t)(rnd >>  8);
        key[i * 4 + 2] = (uint8_t)(rnd >> 16);
        key[i * 4 + 3] = (uint8_t)(rnd >> 24);
    }
    ESP_LOGI(TAG, "Generated random 128-bit key");

    /* Fuzzy extractor enrollment */
    fe_ctx_t fe;
    fe_init(&fe);
    uint8_t helper[FE_HELPER_BYTES];
    fe_enroll(&fe, p_selected, key, helper);
    ESP_LOGI(TAG, "Fuzzy extractor enrollment complete");

    /* POST /enroll to register the device on the server */
    char token_buf[256] = {0};
    auth_result_t res = auth_run(CONFIG_DRONE_DEVICE_ID, key,
                                  CONFIG_DRONE_SERVER_URL,
                                  token_buf, sizeof(token_buf));
    if (res != AUTH_OK) {
        ESP_LOGE(TAG, "Enrollment auth failed (%d) – will retry on reboot", res);
        /* Zeroize key before restart */
        secure_zero(key, sizeof(key));
        secure_zero(&fe, sizeof(fe));
        return; /* Boot count is preserved; next boot will retry /enroll */
    }

    /* Save helper data and mask to NVS */
    if (nvs_save_blob(NVS_KEY_HELPER, helper, sizeof(helper)) != ESP_OK ||
        nvs_save_blob(NVS_KEY_MASK,   vote_state.mask, PUF_RAW_BYTES) != ESP_OK) {
        ESP_LOGE(TAG, "NVS write failed – cannot complete enrollment");
        secure_zero(key, sizeof(key));
        secure_zero(&fe, sizeof(fe));
        return;
    }

    nvs_set_enrolled(1);
    ESP_LOGI(TAG, "Enrollment complete, NVS updated");

    /* Zeroize sensitive data */
    secure_zero(key, sizeof(key));
    secure_zero(p_selected, sizeof(p_selected));
    secure_zero(&fe, sizeof(fe));

    /* Restart into auth mode */
    esp_restart();
}

/* =========================================================================
 * app_main – top-level state machine
 * ========================================================================= */
#ifdef CONFIG_IDF_TARGET
void app_main(void)
#else
int main(void)
#endif
{
    /* Initialize NVS */
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_LOGI(TAG, "NVS initialised");

    drone_state_t state = STATE_BOOT;
    int auth_retries = 0;
    char token[256] = {0};
    long long token_acquired_us = 0;
    uint8_t key[16];
    fe_ctx_t fe;

    while (1) {
        switch (state) {

        /* ---------------------------------------------------------------- */
        case STATE_BOOT:
        /* ---------------------------------------------------------------- */
            ESP_LOGI(TAG, "STATE_BOOT");
            if (nvs_get_enrolled() == 0) {
                /* First boot or enrollment in progress */
                if (vote_state.boot_count == 0) {
                    /* Very first boot: initialise vote_state */
                    memset(&vote_state, 0, sizeof(vote_state));
                    ESP_LOGI(TAG, "Initialising PUF vote state");
                }
                state = STATE_PUF_ENROLL;
            } else {
                state = STATE_PUF_READ;
            }
            break;

        /* ---------------------------------------------------------------- */
        case STATE_PUF_ENROLL:
        /* ---------------------------------------------------------------- */
            ESP_LOGI(TAG, "STATE_PUF_ENROLL (boot %lu/%d)",
                     (unsigned long)vote_state.boot_count, PUF_N_VOTES);
            run_enrollment();
            /* run_enrollment() either calls esp_restart() or returns on error */
            /* If it returned (error), wait and retry next reboot */
            vTaskDelay(pdMS_TO_TICKS(5000));
            esp_restart();
            break;

        /* ---------------------------------------------------------------- */
        case STATE_PUF_READ:
        /* ---------------------------------------------------------------- */
            ESP_LOGI(TAG, "STATE_PUF_READ");
            state = STATE_RECONSTRUCT;
            break;

        /* ---------------------------------------------------------------- */
        case STATE_RECONSTRUCT:
        /* ---------------------------------------------------------------- */
        {
            ESP_LOGI(TAG, "STATE_RECONSTRUCT");

            /* Load helper data and mask from NVS */
            uint8_t helper[FE_HELPER_BYTES];
            uint8_t stored_mask[PUF_RAW_BYTES];

            if (nvs_load_blob(NVS_KEY_HELPER, helper, sizeof(helper)) != ESP_OK ||
                nvs_load_blob(NVS_KEY_MASK, stored_mask, sizeof(stored_mask)) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to load helper/mask from NVS");
                state = STATE_DENY;
                break;
            }

            /* Read raw PUF */
            uint8_t raw[PUF_RAW_BYTES];
            puf_read_raw(raw, sizeof(raw));

            /* Apply stored mask to get this boot's stable bits */
            uint8_t p_prime[PUF_SELECTED];
            puf_select_bits(raw, stored_mask, PUF_RAW_BYTES,
                            p_prime, PUF_SELECTED);

            /* Fuzzy extractor reconstruct */
            fe_init(&fe);
            int rc = fe_reconstruct(&fe, p_prime, helper, key);
            secure_zero(p_prime, sizeof(p_prime));

            if (rc != 0) {
                ESP_LOGE(TAG, "Key reconstruction failed (BCH decode error)");
                secure_zero(key, sizeof(key));
                state = STATE_DENY;
                break;
            }

            ESP_LOGI(TAG, "Key reconstructed successfully");
            state = STATE_NET_CONNECT;
            break;
        }

        /* ---------------------------------------------------------------- */
        case STATE_NET_CONNECT:
        /* ---------------------------------------------------------------- */
            ESP_LOGI(TAG, "STATE_NET_CONNECT");
            if (wifi_connect() != ESP_OK) {
                ESP_LOGE(TAG, "WiFi connection failed");
                secure_zero(key, sizeof(key));
                state = STATE_DENY;
                break;
            }
            ESP_LOGI(TAG, "Network connected");
            auth_retries = 0;
            state = STATE_AUTH;
            break;

        /* ---------------------------------------------------------------- */
        case STATE_AUTH:
        /* ---------------------------------------------------------------- */
            ESP_LOGI(TAG, "STATE_AUTH (attempt %d/%d)",
                     auth_retries + 1, AUTH_MAX_RETRIES);

            memset(token, 0, sizeof(token));
            {
                auth_result_t res = auth_run(CONFIG_DRONE_DEVICE_ID, key,
                                              CONFIG_DRONE_SERVER_URL,
                                              token, sizeof(token));
                if (res == AUTH_OK) {
                    ESP_LOGI(TAG, "Authentication OK");
                    /* Zeroise key immediately after successful auth */
                    secure_zero(key, sizeof(key));
                    token_acquired_us = esp_timer_get_time();
                    auth_retries = 0;
                    /* Start MQTT if not already running */
                    if (!mqtt_client) mqtt_init();
                    state = STATE_LIVE;
                } else {
                    ESP_LOGE(TAG, "Auth failed: %d", (int)res);
                    auth_retries++;
                    if (auth_retries >= AUTH_MAX_RETRIES) {
                        secure_zero(key, sizeof(key));
                        state = STATE_LOCKOUT;
                    } else {
                        vTaskDelay(pdMS_TO_TICKS(2000));
                        /* Remain in STATE_AUTH for retry */
                    }
                }
            }
            break;

        /* ---------------------------------------------------------------- */
        case STATE_LIVE:
        /* ---------------------------------------------------------------- */
        {
            long long now_us = esp_timer_get_time();

            /* Check token expiry */
            if (now_us - token_acquired_us > TOKEN_LIFETIME_US) {
                ESP_LOGW(TAG, "Token expired, re-authenticating");
                /* Must re-derive key (not stored – this is by design) */
                /* For token renewal we'd need to re-read PUF and reconstruct */
                /* Here we do a simplified approach: go back to PUF_READ */
                state = STATE_PUF_READ;
                break;
            }

            /* Publish telemetry */
            publish_telemetry(CONFIG_DRONE_DEVICE_ID, token, now_us);

            vTaskDelay(pdMS_TO_TICKS(TELEMETRY_INTERVAL_MS));
            break;
        }

        /* ---------------------------------------------------------------- */
        case STATE_DENY:
        /* ---------------------------------------------------------------- */
            ESP_LOGE(TAG, "STATE_DENY – authentication failed, inhibiting motors");
            inhibit_motors();
            /* Halt forever */
            while (1) {
                vTaskDelay(pdMS_TO_TICKS(10000));
            }
            break;

        /* ---------------------------------------------------------------- */
        case STATE_LOCKOUT:
        /* ---------------------------------------------------------------- */
            ESP_LOGE(TAG, "STATE_LOCKOUT – too many auth failures, halting");
            inhibit_motors();
            while (1) {
                vTaskDelay(pdMS_TO_TICKS(60000));
                ESP_LOGE(TAG, "Locked out.");
            }
            break;

        default:
            ESP_LOGE(TAG, "Unknown state %d", (int)state);
            state = STATE_DENY;
            break;
        }
    }

#ifndef CONFIG_IDF_TARGET
    return 0;
#endif
}
