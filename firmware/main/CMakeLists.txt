idf_component_register(
    SRCS "main.c" "puf.c" "fuzzy_extractor.c" "auth_client.c"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash esp_wifi esp_netif mqtt mbedtls esp_http_client)
