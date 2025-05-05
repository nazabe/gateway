// Standard C libraries
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

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

// HTTP & JSON
#include "esp_http_client.h"
#include "cJSON.h"

// Other components
#include "wifi_manager.h"
#include "secrets.h"

// TODO: Use docker to fix python & idf problems

#define MAX_FILTER_LIST_SIZE 10
#define MAX_MAC_LEN 18

#define BUFFER_SIZE 500
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

char *DEVICE_UUID = "DEFAULT";
char *DEVICE_MAC = "IM_NOT_A_MAC";             // TODO: Replace with real MAC
char *DEVICE_TOKEN = "THIS_IS_NOT_A_TOKEN";    // TODO: Consider not hardcoding
char *DEVICE_TYPE = "GATEWAY";

char WIFI_SSID[WIFI_SSID_MAX_LEN];
char WIFI_PASS[WIFI_PASS_MAX_LEN];
char wifi_bssid[WIFI_BSSID_MAX_LEN];

int scan_interval = 100;
int scan_window = 100;
int scan_timeout = 5000;

int filter_rssi = -100;
char filter_blacklist[MAX_BLACKLIST_SIZE][18] = {0};
char filter_whitelist[MAX_WHITELIST_SIZE][18] = {0};
char filter_regexMac[FILTER_MAC_REGEX_MAX_LEN];
char filter_regexRaw[FILTER_RAW_REGEX_MAX_LEN];

char mqtt_clientId[MQTT_CLIENT_ID_MAX_LEN] = MQTT_CLIENT_ID;
char mqtt_publishTopic[MQTT_TOPIC_MAX_LEN] = MQTT_PUBLISH_TOPIC;
char mqtt_responseTopic[MQTT_TOPIC_MAX_LEN] = MQTT_RESPONSE_TOPIC;
char mqtt_subscribeTopic[MQTT_TOPIC_MAX_LEN] = MQTT_SUBSCRIBE_TOPIC;
char mqtt_lastWill[MQTT_LAST_WILL_MAX_LEN] = MQTT_LAST_WILL;

static const char *json_str = NULL;
static const char TAG[] = "main";

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

int get_device_uuid(char *DEVICE_MAC, char *DEVICE_TYPE, char *DEVICE_TOKEN) { // TODO: It need have; MAC, Location (AP list), AP, password 

    char wifi_bssid[32] = {0}; // TODO: This is the best way of obtain this variable?

    // Use Wifi-Manager to obtain SSID & Password
    wifi_config_t wifi_config;
    esp_err_t err = esp_wifi_get_config(WIFI_IF_STA, &wifi_config);

    char request_data[256];
    snprintf(request_data, sizeof(request_data), 
             "{\"device_mac\":\"%s\",\"device_type\":\"%s\",\"device_token\":\"%s\",\"wifi_ssid\":\"%s\",\"wifi_password\":\"%s\",\"wifi_password\":\"%s\"}", 
             DEVICE_MAC, DEVICE_TYPE, DEVICE_TOKEN, wifi_config.sta.ssid, wifi_config.sta.password, wifi_bssid); // TODO: Add BSSID

    esp_http_client_config_t config = { // esp_http_client_config_t is undefined, #include "esp_http_client.h" fix it
        .url = UUID_API_URL,
        .method = HTTP_METHOD_POST,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, request_data, strlen(request_data));

    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int http_response_code = esp_http_client_get_status_code(client);
        ESP_LOGI("HTTP", "HTTP Code: %d", http_response_code);

        char response_buffer[128];
        int content_length = esp_http_client_get_content_length(client);
        if (content_length > 0 && content_length < sizeof(response_buffer)) {
            esp_http_client_read(client, response_buffer, content_length);
            response_buffer[content_length] = '\0';
            ESP_LOGI("HTTP", "Response: %s", response_buffer);
        }

        esp_http_client_cleanup(client);
        return http_response_code;
    } else {
        ESP_LOGE("HTTP", "HTTP request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return -1;
    }
}

static cJSON* get_nested_object(cJSON *parent, const char *key, const char *tag) {
    cJSON *item = cJSON_GetObjectItem(parent, key);
    if (item == NULL || !cJSON_IsObject(item)) {
        ESP_LOGE(tag, "Object '%s' not found or invalid.", key);
        return NULL;
    }
    return item;
}

static bool extract_string(cJSON *parent, const char *key, char *dest, size_t dest_size, const char *tag, const char *log_prefix) {
    cJSON *item = cJSON_GetObjectItem(parent, key);
    if (item != NULL && cJSON_IsString(item) && item->valuestring != NULL) {
        strncpy(dest, item->valuestring, dest_size - 1);
        dest[dest_size - 1] = '\0';
        if (log_prefix) {
            ESP_LOGI(tag, "%s: %s", log_prefix, dest);
        }
        return true;
    } else {
       ESP_LOGW(tag, "String '%s' not found or invalid.", key);
       return false;
    }
}

static bool extract_integer(cJSON *parent, const char *key, int *dest, const char *tag, const char *log_prefix) {
    cJSON *item = cJSON_GetObjectItem(parent, key);
    if (item != NULL && cJSON_IsNumber(item)) {
        *dest = item->valueint;
        if (log_prefix) {
            ESP_LOGI(tag, "%s: %d", log_prefix, *dest);
        }
        return true;
    } else {
        ESP_LOGW(tag, "Number '%s' not found or invalid.", key);
        return false;
    }
}

static bool extract_string_array(cJSON *parent, const char *key, char dest_array[][MAX_MAC_LEN], int max_items, size_t item_size, const char *tag, const char *log_prefix) {
    cJSON *array = cJSON_GetObjectItem(parent, key);
    if (array == NULL || !cJSON_IsArray(array)) {
         ESP_LOGW(tag, "Array '%s' not found or invalid.", key);
         return false;
    }

    int list_size = cJSON_GetArraySize(array);
    int items_to_copy = (list_size < max_items) ? list_size : max_items;

    for (int i = 0; i < items_to_copy; i++) {
        cJSON *mac_item = cJSON_GetArrayItem(array, i);
        if (mac_item != NULL && cJSON_IsString(mac_item) && mac_item->valuestring != NULL) {
            strncpy(dest_array[i], mac_item->valuestring, item_size - 1);
            dest_array[i][item_size - 1] = '\0';
            if (log_prefix) {
                 ESP_LOGI(tag, "%s [%d]: %s", log_prefix, i, dest_array[i]);
            }
        } else {
            ESP_LOGW(tag, "Invalid element %d in array '%s'.", i, key);
            dest_array[i][0] = '\0';
        }
    }
     for (int i = items_to_copy; i < max_items; i++) {
         dest_array[i][0] = '\0';
     }
    return true;
}


void process_json_response(const char *json_str) {
    if (json_str == NULL) {
        ESP_LOGE(TAG, "A valid JSON was not received (NULL)");
        return;
    }
    ESP_LOGI(TAG, "JSON received: %s", json_str);

    cJSON *root = cJSON_Parse(json_str);
    if (root == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            ESP_LOGE(TAG, "Error parsing JSON near: %s", error_ptr);
        }
        return;
    }

    cJSON *props = get_nested_object(root, "props", TAG);
    if (!props) {
        cJSON_Delete(root);
        return;
    }

    cJSON *filter = get_nested_object(props, "filter", TAG);
    cJSON *mqtt = get_nested_object(props, "mqtt", TAG);

    if (filter) {
        extract_string_array(filter, "blackList", filter_blacklist, MAX_FILTER_LIST_SIZE, MAX_MAC_LEN, TAG, "Filter blackList MAC");
        extract_string_array(filter, "whiteList", filter_whitelist, MAX_FILTER_LIST_SIZE, MAX_MAC_LEN, TAG, "Filter whiteList MAC");
        extract_string(filter, "regexMac", filter_regexMac, sizeof(filter_regexMac), TAG, "Filter regexMac");
        extract_string(filter, "regexRaw", filter_regexRaw, sizeof(filter_regexRaw), TAG, "Filter regexRaw");
        extract_integer(filter, "rssi", &filter_rssi, TAG, "Filter RSSI");
    }

    if (mqtt) {
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
    if (wifi_array != NULL && cJSON_IsArray(wifi_array)) {
        cJSON *wifi_item = cJSON_GetArrayItem(wifi_array, 0);
        if (wifi_item != NULL && cJSON_IsObject(wifi_item)) {
            extract_string(wifi_item, "ssid", WIFI_SSID, sizeof(WIFI_SSID), TAG, "Wi-Fi SSID");
            extract_string(wifi_item, "password", WIFI_PASS, sizeof(WIFI_PASS), TAG, "Wi-Fi Password");
            extract_string(wifi_item, "bssid", wifi_bssid, sizeof(wifi_bssid), TAG, "Wi-Fi BSSID");
        } else {
            ESP_LOGE(TAG, "The first element of the 'wifi' array is not a valid object.");
        }
    } else {
        ESP_LOGE(TAG, "Array 'wifi' not found or invalid.");
    }

    cJSON_Delete(root);
}

esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    static char *response_buffer = NULL;
    static int response_len = 0;

    switch (evt->event_id) {
        case HTTP_EVENT_ON_HEADER:
            // ESP_LOGI(TAG, "Header received: %.*s", evt->data_len, (char *)evt->data);
            break;

        case HTTP_EVENT_ON_DATA:
            if (esp_http_client_is_chunked_response(evt->client)) break;

            char *new_buf = realloc(response_buffer, response_len + evt->data_len + 1);
            if (!new_buf) {
                ESP_LOGE(TAG, "Error when asign memory");
                free(response_buffer);
                response_buffer = NULL;
                response_len = 0;
                return ESP_FAIL;
            }

            response_buffer = new_buf;
            memcpy(response_buffer + response_len, evt->data, evt->data_len);
            response_len += evt->data_len;
            response_buffer[response_len] = '\0';
            break;

        case HTTP_EVENT_ON_FINISH:
            if (response_buffer) {
                json_str = response_buffer;
                process_json_response(json_str);
                free(response_buffer);
                response_buffer = NULL;
                response_len = 0;
            }
            break;

        case HTTP_EVENT_DISCONNECTED:
            free(response_buffer);
            response_buffer = NULL;
            response_len = 0;
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

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    esp_http_client_cleanup(client);

    ESP_LOGI(TAG, "HTTP GET %s", err == ESP_OK ? "successful" : esp_err_to_name(err));
    return err;
}

void app_main(void)
{

	/* start the wifi manager */
	wifi_manager_init();
	wifi_manager_start();

	while (!is_wifi_connected()) {vTaskDelay(pdMS_TO_TICKS(500));}

	// TODO: If lost wifi connection per more than 10 min, start modem

	if (strcmp(DEVICE_UUID, "DEFAULT")) // TODO: It have to update DEVICE_UUID
	{
		get_device_uuid(DEVICE_MAC, DEVICE_TOKEN, DEVICE_TYPE);
	}

    ESP_ERROR_CHECK(update_config());

}