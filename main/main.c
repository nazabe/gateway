// Standard C libraries
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>

// FreeRTOS
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// ESP-IDF logging and system
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_crt_bundle.h"

// Networking
#include "esp_wifi.h"
#include "esp_netif.h"
#include "lwip/ip4_addr.h"
#include "esp_sntp.h"
#include "mqtt_client.h"

// NimBLE stack
#include "esp_nimble_hci.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"

// NVS and bootloader
#include "nvs_flash.h"
#include "bootloader_random.h"
#include "nvs.h"

// HTTP & JSON
#include "esp_http_client.h"
#include "cJSON.h"

// OTA
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"

// Other components
#include "wifi_manager.h"
#include "secrets.h"

// TODO: Use docker to fix python & idf problems

#define MAX_FILTER_LIST_SIZE 10
#define MAX_MAC_LEN 18

#define CLEAN_INTERVAL_MS 5000

#define WIFI_SSID_MAX_LEN 32
#define WIFI_PASS_MAX_LEN 64
#define WIFI_BSSID_MAX_LEN 18

#define FILTER_MAC_REGEX_MAX_LEN 64
#define FILTER_RAW_REGEX_MAX_LEN 64

#define MAX_BLACKLIST_SIZE 10
#define MAX_WHITELIST_SIZE 10

#define MQTT_CLIENT_ID_MAX_LEN 64
#define MQTT_LAST_WILL_MAX_LEN 128
#define MQTT_TOPIC_MAX_LEN 128

char DEVICE_MAC[13];
char *DEVICE_TOKEN1 = "THIS_IS_NOT_A_TOKEN"; // TODO: Consider not hardcoding
char *DEVICE_TOKEN2 = "THIS_IS_NOT_A_TOKEN";
char *DEVICE_TYPE = "GATEWAY";

char WIFI_SSID[WIFI_SSID_MAX_LEN];
char WIFI_PASS[WIFI_PASS_MAX_LEN];
char wifi_bssid[WIFI_BSSID_MAX_LEN];

uint16_t scan_interval = 100;
uint16_t scan_window = 100;
uint16_t scan_timeout = 60 * 1000;

uint8_t filter_policy = 0;
uint8_t limited = 0;
uint8_t passive = 1;
uint8_t filter_duplicates = 1;

int filter_rssi = -100;
char filter_blacklist[MAX_BLACKLIST_SIZE][18] = {0};
char filter_whitelist[MAX_WHITELIST_SIZE][18] = {0};
char filter_regexMac[FILTER_MAC_REGEX_MAX_LEN];
char filter_regexRaw[FILTER_RAW_REGEX_MAX_LEN];

char mqtt_clientId[MQTT_CLIENT_ID_MAX_LEN] = DEVICE_UUID;
char mqtt_publishTopic[MQTT_TOPIC_MAX_LEN] = MQTT_PUBLISH_TOPIC;
char mqtt_responseTopic[MQTT_TOPIC_MAX_LEN] = MQTT_RESPONSE_TOPIC;
char mqtt_subscribeTopic[MQTT_TOPIC_MAX_LEN] = MQTT_SUBSCRIBE_TOPIC;
char mqtt_lastWill[MQTT_LAST_WILL_MAX_LEN] = MQTT_LAST_WILL;

#define MAX_HTTP_RESPONSE_SIZE 2048
#define MAX_HTTP_BUFFER_SIZE (MAX_HTTP_RESPONSE_SIZE + 1)

static char http_response_buffer[MAX_HTTP_BUFFER_SIZE];

// Configuration for NTP
#define NTP_SERVER_HOSTNAME "time.google.com" // "pool.ntp.org"
#define NTP_RETRY_DELAY_MS 1000

static bool sntp_initialized_flag = false;
static volatile bool sntp_sync_done = false;

typedef struct
{
    uint8_t mac[6];      // "XX:XX:XX:XX:XX:XX" + null.
    int8_t rssi;         // integer value, normally negative
    uint8_t raw_adv[31]; // 31 * 2 = 62 bytes → 124 chars + \0 = 125 bytes
    uint8_t raw_len;
    uint64_t timestamp_ms; // Time (ej. ISO 8601)
} ble_packet_raw_t;

#define DEVICES_COUNTER 80

QueueHandle_t ble_queue;
esp_mqtt_client_handle_t mqtt_client;

static const char hex_chars[] = "0123456789ABCDEF";

#define MAX_FILE_LEN (1300 * 1024) // OTA Image
#define OTA_RETRY_DELAY 15 * 1000

uint32_t file_len = 0;
uint32_t sum = 0;
static int last_log_percent = -5;

volatile bool do_ota = false;
volatile bool mqtt_connected = false;

static const char *json_str = NULL;
static const char TAG[] = "main";

void ble_app_scan(void);

esp_http_client_handle_t client;

bool is_wifi_connected()
{
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
    {
        return true;
    }
    return false;
}

int get_device_uuid(char *DEVICE_MAC, char *DEVICE_TYPE, char *DEVICE_TOKEN1)
{ // TODO: It need have; Location (AP list), Flash ID, Token (or tokens)

    // Use Wifi-Manager to obtain SSID & Password
    wifi_config_t wifi_config;
    esp_err_t err = esp_wifi_get_config(WIFI_IF_STA, &wifi_config);

    char request_data[256];

    // TODO: Replace per memcpy
    snprintf(request_data, sizeof(request_data),
             "{\"device_mac\":\"%s\",\"device_type\":\"%s\",\"device_token\":\"%s\",\"wifi_ssid\":\"%s\",\"wifi_password\":\"%s\"}",
             DEVICE_MAC, DEVICE_TYPE, DEVICE_TOKEN1, wifi_config.sta.ssid, wifi_config.sta.password);

    esp_http_client_config_t config = {
        // esp_http_client_config_t is undefined, #include "esp_http_client.h" fix it
        .url = UUID_API_URL,
        .method = HTTP_METHOD_POST,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, request_data, strlen(request_data));

    err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        int http_response_code = esp_http_client_get_status_code(client);
        ESP_LOGI("HTTP", "HTTP Code: %d", http_response_code);

        char output_buffer[128];
        int content_length = esp_http_client_get_content_length(client);
        if (content_length > 0 && content_length < sizeof(output_buffer))
        {
            esp_http_client_read(client, output_buffer, content_length);
            output_buffer[content_length] = '\0';
            ESP_LOGI("HTTP", "Response: %s", output_buffer);
        }

        esp_http_client_cleanup(client);
        return http_response_code;
    }
    else
    {
        ESP_LOGE("HTTP", "HTTP request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return -1;
    }
}

static cJSON *get_nested_object(cJSON *parent, const char *key, const char *tag)
{
    cJSON *item = cJSON_GetObjectItem(parent, key);
    if (item == NULL || !cJSON_IsObject(item))
    {
        ESP_LOGE(tag, "Object '%s' not found or invalid.", key);
        return NULL;
    }
    return item;
}

static bool extract_string(cJSON *parent, const char *key, char *dest, size_t dest_size, const char *tag, const char *log_prefix)
{
    cJSON *item = cJSON_GetObjectItem(parent, key);
    if (item != NULL && cJSON_IsString(item) && item->valuestring != NULL)
    {
        strncpy(dest, item->valuestring, dest_size - 1);
        dest[dest_size - 1] = '\0';
        // NOTE: Commented out to avoid invasive logging; uncomment for debug if needed.
        // if (log_prefix) {ESP_LOGI(tag, "%s: %s", log_prefix, dest);}
        return true;
    }
    else
    {
        ESP_LOGW(tag, "String '%s' not found or invalid.", key);
        return false;
    }
}

static bool extract_integer(cJSON *parent, const char *key, int *dest, const char *tag, const char *log_prefix)
{
    cJSON *item = cJSON_GetObjectItem(parent, key);
    if (item != NULL && cJSON_IsNumber(item))
    {
        *dest = item->valueint;
        if (log_prefix)
        {
            ESP_LOGI(tag, "%s: %d", log_prefix, *dest);
        }
        return true;
    }
    else
    {
        ESP_LOGW(tag, "Number '%s' not found or invalid.", key);
        return false;
    }
}

static bool extract_string_array(cJSON *parent, const char *key, char dest_array[][MAX_MAC_LEN], int max_items, size_t item_size, const char *tag, const char *log_prefix)
{
    cJSON *array = cJSON_GetObjectItem(parent, key);
    if (array == NULL || !cJSON_IsArray(array))
    {
        ESP_LOGW(tag, "Array '%s' not found or invalid.", key);
        return false;
    }

    int list_size = cJSON_GetArraySize(array);
    int items_to_copy = (list_size < max_items) ? list_size : max_items;

    for (int i = 0; i < items_to_copy; i++)
    {
        cJSON *mac_item = cJSON_GetArrayItem(array, i);
        if (mac_item != NULL && cJSON_IsString(mac_item) && mac_item->valuestring != NULL)
        {
            strncpy(dest_array[i], mac_item->valuestring, item_size - 1);
            dest_array[i][item_size - 1] = '\0';
            if (log_prefix)
            {
                ESP_LOGI(tag, "%s [%d]: %s", log_prefix, i, dest_array[i]);
            }
        }
        else
        {
            ESP_LOGW(tag, "Invalid element %d in array '%s'.", i, key);
            dest_array[i][0] = '\0';
        }
    }
    for (int i = items_to_copy; i < max_items; i++)
    {
        dest_array[i][0] = '\0';
    }
    return true;
}

void process_json_response(const char *json_str)
{
    if (json_str == NULL)
    {
        ESP_LOGE(TAG, "A valid JSON was not received (NULL)");
        return;
    }
    ESP_LOGI(TAG, "JSON received: %s", json_str);

    cJSON *root = cJSON_Parse(json_str);
    if (root == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            ESP_LOGE(TAG, "Error parsing JSON near: %s", error_ptr);
        }
        return;
    }

    cJSON *props = get_nested_object(root, "props", TAG);
    if (!props)
    {
        cJSON_Delete(root);
        return;
    }

    cJSON *filter = get_nested_object(props, "filter", TAG);
    cJSON *mqtt = get_nested_object(props, "mqtt", TAG);

    if (filter)
    {
        extract_string_array(filter, "blackList", filter_blacklist, MAX_FILTER_LIST_SIZE, MAX_MAC_LEN, TAG, "Filter blackList MAC");
        extract_string_array(filter, "whiteList", filter_whitelist, MAX_FILTER_LIST_SIZE, MAX_MAC_LEN, TAG, "Filter whiteList MAC");
        extract_string(filter, "regexMac", filter_regexMac, sizeof(filter_regexMac), TAG, "Filter regexMac");
        extract_string(filter, "regexRaw", filter_regexRaw, sizeof(filter_regexRaw), TAG, "Filter regexRaw");
        extract_integer(filter, "rssi", &filter_rssi, TAG, "Filter RSSI");
    }

    if (mqtt)
    {
        extract_string(mqtt, "clientId", mqtt_clientId, sizeof(mqtt_clientId), TAG, "MQTT clientId");
        extract_integer(mqtt, "keepalive", &mqtt_keepalive, TAG, "MQTT keepalive");
        extract_string(mqtt, "lastWill", mqtt_lastWill, sizeof(mqtt_lastWill), TAG, "MQTT lastWill");
        extract_string(mqtt, "password", mqtt_password, sizeof(mqtt_password), TAG, "MQTT password");
        extract_string(mqtt, "publishTopic", mqtt_publishTopic, sizeof(mqtt_publishTopic), TAG, "MQTT publishTopic");
        extract_integer(mqtt, "qos", &mqtt_qos, TAG, "MQTT QoS");
        extract_string(mqtt, "responseTopic", mqtt_responseTopic, sizeof(mqtt_responseTopic), TAG, "MQTT responseTopic");
        extract_string(mqtt, "subscribeTopic", mqtt_subscribeTopic, sizeof(mqtt_subscribeTopic), TAG, "MQTT subscribeTopic");
        extract_string(mqtt, "url", mqtt_url, sizeof(mqtt_url), TAG, "MQTT url");
        extract_string(mqtt, "userName", mqtt_userName, sizeof(mqtt_userName), TAG, "MQTT userName");
    }

    cJSON *wifi_array = cJSON_GetObjectItem(props, "wifi");
    if (wifi_array != NULL && cJSON_IsArray(wifi_array))
    {
        cJSON *wifi_item = cJSON_GetArrayItem(wifi_array, 0);
        if (wifi_item != NULL && cJSON_IsObject(wifi_item))
        {
            extract_string(wifi_item, "ssid", WIFI_SSID, sizeof(WIFI_SSID), TAG, "Wi-Fi SSID");
            extract_string(wifi_item, "password", WIFI_PASS, sizeof(WIFI_PASS), TAG, "Wi-Fi Password");
            extract_string(wifi_item, "bssid", wifi_bssid, sizeof(wifi_bssid), TAG, "Wi-Fi BSSID");
        }
        else
        {
            ESP_LOGE(TAG, "The first element of the 'wifi' array is not a valid object.");
        }
    }
    else
    {
        ESP_LOGE(TAG, "Array 'wifi' not found or invalid.");
    }

    cJSON_Delete(root);
}

esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer; // Buffer to store response of http request from event handler
    static int response_len = 0;

    switch (evt->event_id)
    {
    case HTTP_EVENT_ERROR:
        ESP_LOGE(TAG, "HTTP_EVENT_ERROR");
        break;

    case HTTP_EVENT_ON_HEADER:
        if (evt->header_key && strcmp(evt->header_key, "size") == 0)
        {
            file_len = strtol(evt->header_value, NULL, 10);
            if (file_len > 0 && file_len < MAX_FILE_LEN)
            {
                ESP_LOGI(TAG, "Set len: %lu bytes", (uint32_t)file_len);
            }
            else
            {
                ESP_LOGW(TAG, "Invalid or too large file_len: %ld", file_len);
                file_len = 0;
            }
        }
        break;

    case HTTP_EVENT_ON_DATA:
        if (esp_http_client_is_chunked_response(evt->client))
            break;

        if (evt->data)
        {
            if (response_len + evt->data_len <= MAX_HTTP_RESPONSE_SIZE)
            {
                memcpy(http_response_buffer + response_len, evt->data, evt->data_len);
                response_len += evt->data_len;
                http_response_buffer[response_len] = '\0';
            }
            else
            {
                ESP_LOGW(TAG, "HTTP response buffer overflow or null data");
                http_response_buffer[MAX_HTTP_RESPONSE_SIZE - 1] = '\0';
            }
        }

        if (file_len > 0)
        {
            sum += evt->data_len;
            int percent = (int)(sum * 100 / file_len);

            if (percent != last_log_percent && percent % 5 == 0)
            {
                ESP_LOGI(TAG, "Progress: %lu/%lu bytes (%d%%)", sum, file_len, percent);
                last_log_percent = percent;
            }
        }
        break;

    case HTTP_EVENT_ON_FINISH:
        if (output_buffer)
        {
            json_str = output_buffer;
            process_json_response(json_str);
            free(output_buffer);
            output_buffer = NULL;
            response_len = 0;
        }
        sum = 0;
        last_log_percent = -1;
        break;

    case HTTP_EVENT_DISCONNECTED:
        free(output_buffer);
        output_buffer = NULL;
        response_len = 0;
        sum = 0;
        last_log_percent = -1;
        break;

    default:
        break;
    }

    return ESP_OK;
}

esp_err_t update_config()
{
    esp_http_client_config_t config = {
        .url = CONFIG_API_URL,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = http_event_handler,
        .timeout_ms = 5000,
    };

    client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    esp_http_client_cleanup(client);

    ESP_LOGI(TAG, "HTTP GET %s", err == ESP_OK ? "successful" : esp_err_to_name(err));
    return err;
}

static void time_sync_notification_cb(struct timeval *tv)
{
    sntp_sync_done = true;
    ESP_LOGI(TAG, "NTP: Time sync callback fired");
}

void ntp_sync(void)
{
    ESP_LOGI(TAG, "NTP: Starting synchronization process...");

    if (!sntp_initialized_flag)
    {
        ESP_LOGI(TAG, "NTP: SNTP not initialized. Initializing now...");

        esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, NTP_SERVER_HOSTNAME);
        // esp_sntp_setservername(0, "216.239.35.0"); // NOTE: Use IP if DNS fails

        ESP_LOGI(TAG, "NTP: Configured server: %s", esp_sntp_getservername(0));
        esp_sntp_set_time_sync_notification_cb(time_sync_notification_cb);

        esp_sntp_init();
        sntp_initialized_flag = true;
        ESP_LOGI(TAG, "NTP: SNTP initialized. Waiting for synchronization...");
    }
    else
    {
        ESP_LOGI(TAG, "NTP: SNTP already initialized. Verifying status...");

        if (!esp_sntp_enabled())
        {
            ESP_LOGW(TAG, "NTP: SNTP was disabled. Re-initializing...");
            esp_sntp_init();
        }
        else
        {
            ESP_LOGI(TAG, "NTP: SNTP is already running.");
        }
    }

    ESP_LOGI(TAG, "NTP: Checking sync status before waiting...");

    while (!sntp_sync_done)
    {
        ESP_LOGI(TAG, "NTP: Waiting for system time to be set...");
        ESP_LOGI(TAG, "NTP: Current SNTP sync status: %d", sntp_get_sync_status());
        vTaskDelay(pdMS_TO_TICKS(NTP_RETRY_DELAY_MS));
    }

    if (sntp_sync_done && sntp_get_sync_status() == SNTP_SYNC_STATUS_COMPLETED)
    {
        ESP_LOGI(TAG, "NTP: Time synchronized successfully!");

        // Log the synchronized time
        time_t now;
        struct tm timeinfo;
        char strftime_buf[64];

        time(&now);
        setenv("TZ", "UTC+3", 1); // Set to your local timezone
        tzset();

        localtime_r(&now, &timeinfo);
        strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
        ESP_LOGI(TAG, "NTP: Current system time: %s", strftime_buf);
    }
    else
    {
        ESP_LOGE(TAG, "NTP: Time synchronization failed.");
        ESP_LOGI(TAG, "NTP: Final SNTP sync status: %d (0: Reset, 1: Completed, 2: InProgress)", sntp_get_sync_status());
        sntp_initialized_flag = false; // Allow reinit on next attempt
    }

    ESP_LOGI(TAG, "NTP: SNTP is currently %s", esp_sntp_enabled() ? "enabled" : "disabled");
    ESP_LOGI(TAG, "NTP: Using server: %s", esp_sntp_getservername(0));
}

void init_device_mac()
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    for (int i = 0; i < 6; i++)
    {
        DEVICE_MAC[i * 2] = hex_chars[(mac[i] >> 4) & 0x0F];
        DEVICE_MAC[i * 2 + 1] = hex_chars[mac[i] & 0x0F];
    }
    DEVICE_MAC[12] = '\0'; // Null-terminador
}

static inline char nibble_to_hex(uint8_t nibble)
{
    return (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
}

static int ble_scan_callback(struct ble_gap_event *event, void *arg)
{
    // REFERENCE:
    // https://github.com/espressif/esp-idf/blob/master/examples/bluetooth/nimble/blecent/tutorial/blecent_walkthrough.md

    switch (event->type)
    {
    case BLE_GAP_EVENT_EXT_DISC:
    case BLE_GAP_EVENT_DISC:
    {
        if (event->disc.data == NULL || event->disc.addr.val[0] == 0)
            return 0;

        struct ble_hs_adv_fields fields;
        int rc = ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data);
        if (rc != 0)
        {
            ESP_EARLY_LOGW(TAG, "Failed to parse BLE advertisement data");
            return 0;
        }

        ble_packet_raw_t pkt = {0};

        memcpy(pkt.mac, event->disc.addr.val, 6);
        pkt.rssi = event->disc.rssi;

        pkt.raw_len = event->disc.length_data > sizeof(pkt.raw_adv) ? sizeof(pkt.raw_adv) : event->disc.length_data;
        memcpy(pkt.raw_adv, event->disc.data, pkt.raw_len);

        struct timeval tv;
        gettimeofday(&tv, NULL);
        pkt.timestamp_ms = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

        xQueueSend(ble_queue, &pkt, 0);
        break;
    }

    case BLE_GAP_EVENT_DISC_COMPLETE:
        // ESP_EARLY_LOGI(TAG, "Scan complete. Scanning again...");
        ble_app_scan();
        break;

    default:
        ESP_EARLY_LOGW(TAG, "Unhandled BLE event: %d", event->type);
        break;
    }
    return 0;
}

void ble_app_scan(void)
{
    struct ble_gap_disc_params disc_params = {
        .itvl = scan_interval,
        .window = scan_window,
        .filter_policy = filter_policy,
        .limited = limited,
        .passive = passive,
        .filter_duplicates = filter_duplicates,
    };

    ble_gap_disc(0, scan_timeout, &disc_params, ble_scan_callback, NULL);
}

void ota_task(void *pvParameter)
{
    ESP_LOGI(TAG, "OTA task started");

    const esp_http_client_config_t config = {
        .url = OTA_URL,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .skip_cert_common_name_check = true,
    };

    const esp_https_ota_config_t ota_config = {
        .http_config = &config,
    };

    // NOTE: This is only for debug
    // vTaskDelay(pdMS_TO_TICKS(10000));
    // do_ota = true;

    while (1)
    {
        // TODO: This flag need to be set via MQTT
        if (!do_ota)
        {
            // ESP_LOGI(TAG, "do_ota is false, waiting...");
            vTaskDelay(pdMS_TO_TICKS(OTA_RETRY_DELAY));
            continue;
        }

        ESP_LOGI(TAG, "Starting OTA...");

        esp_err_t ret = esp_https_ota(&ota_config);

        UBaseType_t watermark = uxTaskGetStackHighWaterMark(NULL);
        ESP_LOGI(TAG, "Stack high water mark: %lu words (%lu bytes)", watermark, watermark * sizeof(StackType_t));

        if (ret == ESP_OK)
        {
            ESP_LOGI(TAG, "OTA success, restarting...");
            esp_restart();
        }
        else
        {
            ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(ret));
        }

        do_ota = false; // Reset the flag

        vTaskDelay(pdMS_TO_TICKS(10000)); // Prevent hammering the server on repeated failure
    }
}

void ble_host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void ble_json_task(void *param)
{
    ble_packet_raw_t pkt, buffer[DEVICES_COUNTER];
    int count = 0;

    // TODO: Validate devices via black & white list. Add gateway data in JSON

    while (1)
    {
        // Try to receive from queue with timeout
        if (xQueueReceive(ble_queue, &pkt, pdMS_TO_TICKS(CLEAN_INTERVAL_MS)) == pdTRUE)
        {
            if (count < DEVICES_COUNTER)
                buffer[count++] = pkt;
        }
        else if (count == 0)
        {
            // Timeout with no data → wait again
            continue;
        }

        if (count < DEVICES_COUNTER)
            continue;

        cJSON *root = cJSON_CreateObject(), *arr = cJSON_CreateArray();
        if (!root || !arr)
        {
            ESP_LOGE(TAG, "Failed to create JSON object/array");
            if (root)
                cJSON_Delete(root);
            count = 0;
            continue;
        }

        cJSON_AddItemToObject(root, "devices", arr);

        for (int i = 0; i < count; i++)
        {
            cJSON *entry = cJSON_CreateObject();
            if (!entry)
            {
                ESP_LOGW(TAG, "Failed to create JSON entry");
                continue;
            }

            char mac[18], raw[63] = {0}, timestamp[40];
            snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
                     buffer[i].mac[0], buffer[i].mac[1], buffer[i].mac[2],
                     buffer[i].mac[3], buffer[i].mac[4], buffer[i].mac[5]);

            int len = buffer[i].raw_len > 31 ? 31 : buffer[i].raw_len;
            for (int j = 0; j < len; j++)
                snprintf(raw + j * 2, 3, "%02X", buffer[i].raw_adv[j]);

            time_t sec = buffer[i].timestamp_ms / 1000;
            int ms = buffer[i].timestamp_ms % 1000;
            struct tm t;
            localtime_r(&sec, &t);
            snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec, ms);

            cJSON_AddStringToObject(entry, "mac", mac);
            cJSON_AddNumberToObject(entry, "rssi", buffer[i].rssi);
            cJSON_AddStringToObject(entry, "timestamp", timestamp);
            cJSON_AddStringToObject(entry, "raw", raw);
            cJSON_AddItemToArray(arr, entry);
        }

        char *json = cJSON_PrintUnformatted(root);
        if (json)
        {
            // send_json_via_mqtt(json);
            ESP_LOGI(TAG, "JSON: %s", json);
            free(json);
        }
        else
        {
            ESP_LOGE(TAG, "Failed to convert JSON to string");
        }

        cJSON_Delete(root);
        count = 0;
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

void mqtt_event_handler(void *args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = event_data;

    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
        mqtt_connected = true;
        ESP_LOGI(TAG, "MQTT connected");

        if (mqtt_client) {
            esp_mqtt_client_subscribe(mqtt_client, MQTT_SUBSCRIBE_TOPIC, 0);
            ESP_LOGI(TAG, "Subscribed to OTA topic: %s", MQTT_SUBSCRIBE_TOPIC);
        }
        break;

    case MQTT_EVENT_DISCONNECTED:
        mqtt_connected = false;
        ESP_LOGW(TAG, "MQTT disconnected");
        break;

    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT event data received");

        char topic[128] = {0};
        char data[128] = {0};

        int topic_len = event->topic_len < sizeof(topic) - 1 ? event->topic_len : sizeof(topic) - 1;
        int data_len = event->data_len < sizeof(data) - 1 ? event->data_len : sizeof(data) - 1;

        memcpy(topic, event->topic, topic_len);
        memcpy(data, event->data, data_len);

        if (strcmp(topic, MQTT_SUBSCRIBE_TOPIC) == 0 && strcmp(data, "ota_update") == 0)
        {
            do_ota = true;
            ESP_LOGI(TAG, "OTA update requested");
        }
        break;

    default:
        ESP_LOGD(TAG, "Unhandled MQTT event ID: %d", event_id);
        break;
    }
}

char mqtt_topic[64];

static void mqtt_init(void)
{
    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = mqtt_url,
        .broker.verification.crt_bundle_attach = esp_crt_bundle_attach,
    };

    mqtt_client = esp_mqtt_client_init(&cfg);
    if (!mqtt_client) {
        ESP_LOGE(TAG, "Failed to initialize MQTT client");
        return;
    }

    if (esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register MQTT event handler");
        return;
    }

    if (esp_mqtt_client_start(mqtt_client) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start MQTT client");
        return;
    }

    // Topic de publicación, usando MAC como ID
    uint8_t mac[6];
    if (esp_efuse_mac_get_default(mac) == ESP_OK) {
        snprintf(mqtt_topic, sizeof(mqtt_topic), MQTT_TOPIC_TEMPLATE,
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        snprintf(mqtt_topic, sizeof(mqtt_topic), MQTT_RESPONSE_TOPIC);
    }
}

void app_main(void)
{
    init_device_mac();

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        // NVS partition was truncated and needs to be erased
        // Retry nvs_flash_init
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    /* start the wifi manager */
    wifi_manager_init();
    wifi_manager_start();

    while (!is_wifi_connected())
    {
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    // TODO: If lost wifi connection per more than 10 min, start modem

    if (strcmp(DEVICE_UUID, "DEFAULT")) // TODO: It have to update DEVICE_UUID
    {
        get_device_uuid(DEVICE_MAC, DEVICE_TOKEN1, DEVICE_TYPE);
    }

    ESP_ERROR_CHECK(update_config());

    ntp_sync();

    ble_queue = xQueueCreate(DEVICES_COUNTER, sizeof(ble_packet_raw_t));
    if (ble_queue == NULL)
    {
        ESP_LOGE(TAG, "Cannot start BLE Queue");
    }

    esp_nimble_hci_init();
    nimble_port_init();
    ble_gattc_init();

    ble_hs_cfg.sync_cb = ble_app_scan;
    nimble_port_freertos_init(ble_host_task);

    xTaskCreatePinnedToCore(ble_json_task, "ble_json_task", 8192, NULL, 5, NULL, tskNO_AFFINITY);
    xTaskCreatePinnedToCore(ota_task, "OTA", 4096, NULL, 7, NULL, tskNO_AFFINITY);
}