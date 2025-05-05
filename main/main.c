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

int get_device_uuid(char *DEVICE_MAC, char *DEVICE_TYPE, char *DEVICE_TOKEN) {

    char wifi_bssid[32] = {0}; // TODO: This is the best way of obtain this variable?

    // Use Wifi-Manager to obtain SSID & Password
    wifi_config_t wifi_config;
    esp_err_t err = esp_wifi_get_config(WIFI_IF_STA, &wifi_config);

    char request_data[256];
    snprintf(request_data, sizeof(request_data), 
             "{\"device_mac\":\"%s\",\"device_type\":\"%s\",\"device_token\":\"%s\",\"wifi_ssid\":\"%s\",\"wifi_password\":\"%s\",\"wifi_password\":\"%s\"}", 
             DEVICE_MAC, DEVICE_TYPE, DEVICE_TOKEN, wifi_config.sta.ssid, wifi_config.sta.password, wifi_bssid); // TODO: Add BSSID

    esp_http_client_config_t config = { // esp_http_client_config_t is undefined, #include "esp_http_client.h" fix it
        .url = API_URL,
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

void handle_json_response(const char *json_str) {

    if (json_str == NULL) {
        ESP_LOGE(TAG, "No se recibió un JSON válido");
        return;
    }

    ESP_LOGI(TAG, "JSON recibido: %s", json_str);

    // Parsear el JSON
    cJSON *root = cJSON_Parse(json_str);
    if (root == NULL) {
        ESP_LOGE(TAG, "Error al parsear el JSON");
        return;
    }

    // Navegar al campo props.mqtt.url
    cJSON *props = cJSON_GetObjectItem(root, "props");
    if (props == NULL || !cJSON_IsObject(props)) {
        ESP_LOGE(TAG, "No se encontró el objeto 'props' en el JSON");
        cJSON_Delete(root);
        return;
    }

    // Navegar al campo filter dentro de props
    cJSON *filter = cJSON_GetObjectItem(props, "filter");
    if (filter == NULL || !cJSON_IsObject(filter)) {
        ESP_LOGE(TAG, "No se encontró el objeto 'filter' en el JSON");
        cJSON_Delete(root);
        return;
    }

    // Leer blackList (lista de MACs)
    cJSON *blackList = cJSON_GetObjectItem(filter, "blackList");
    if (blackList != NULL && cJSON_IsArray(blackList)) {
        int list_size = cJSON_GetArraySize(blackList);
        for (int i = 0; i < list_size && i < 10; i++) {  // Suponemos que no hay más de 10 MACs
            cJSON *mac_item = cJSON_GetArrayItem(blackList, i);
            if (mac_item != NULL && cJSON_IsString(mac_item)) {
                strncpy(filter_blacklist[i], mac_item->valuestring, sizeof(filter_blacklist[i]) - 1);
                filter_blacklist[i][sizeof(filter_blacklist[i]) - 1] = '\0'; // Asegurar terminación nula
            }
        }
    }

    // Leer whiteList (lista de MACs)
    cJSON *whiteList = cJSON_GetObjectItem(filter, "whiteList");
    if (whiteList != NULL && cJSON_IsArray(whiteList)) {
        int list_size = cJSON_GetArraySize(whiteList);
        for (int i = 0; i < list_size && i < 10; i++) {  // Suponemos que no hay más de 10 MACs
            cJSON *mac_item = cJSON_GetArrayItem(whiteList, i);
            if (mac_item != NULL && cJSON_IsString(mac_item)) {
                strncpy(filter_whitelist[i], mac_item->valuestring, sizeof(filter_whitelist[i]) - 1);
                filter_whitelist[i][sizeof(filter_whitelist[i]) - 1] = '\0'; // Asegurar terminación nula
            }
        }
    }

    // Leer regexMac
    cJSON *regexMac = cJSON_GetObjectItem(filter, "regexMac");
    if (regexMac != NULL && cJSON_IsString(regexMac)) {
        strncpy(filter_regexMac, regexMac->valuestring, sizeof(filter_regexMac) - 1);
        filter_regexMac[sizeof(filter_regexMac) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "Filter regexMac: %s", filter_regexMac);
    }

    // Leer regexRaw
    cJSON *regexRaw = cJSON_GetObjectItem(filter, "regexRaw");
    if (regexRaw != NULL && cJSON_IsString(regexRaw)) {
        strncpy(filter_regexRaw, regexRaw->valuestring, sizeof(filter_regexRaw) - 1);
        filter_regexRaw[sizeof(filter_regexRaw) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "Filter regexRaw: %s", filter_regexRaw);
    }

    // Leer rssi
    cJSON *rssi = cJSON_GetObjectItem(filter, "rssi");
    if (rssi != NULL && cJSON_IsNumber(rssi)) {
        filter_rssi = rssi->valueint;
        ESP_LOGI(TAG, "Filter RSSI: %d", filter_rssi);
    }

    // Navegar al campo mqtt dentro de props
    cJSON *mqtt = cJSON_GetObjectItem(props, "mqtt");
    if (mqtt == NULL || !cJSON_IsObject(mqtt)) {
        ESP_LOGE(TAG, "No se encontró el objeto 'mqtt' en el JSON");
        cJSON_Delete(root);
        return;
    }

    // Leer clientId
    cJSON *clientId = cJSON_GetObjectItem(mqtt, "clientId");
    if (clientId && cJSON_IsString(clientId)) {
        strncat(mqtt_clientId, clientId->valuestring, sizeof(mqtt_clientId) - strlen(mqtt_clientId) - 1);
        ESP_LOGI(TAG, "MQTT clientId: %s", mqtt_clientId);
    }

    // Leer keepalive
    cJSON *keepalive = cJSON_GetObjectItem(mqtt, "keepalive");
    if (keepalive != NULL && cJSON_IsNumber(keepalive)) {
        mqtt_keepalive = keepalive->valueint;
        ESP_LOGI(TAG, "MQTT keepalive: %d", mqtt_keepalive);
    }

    // Leer lastWill
    cJSON *lastWill = cJSON_GetObjectItem(mqtt, "lastWill");
    if (lastWill != NULL && cJSON_IsString(lastWill)) {
        strncpy(mqtt_lastWill, lastWill->valuestring, sizeof(mqtt_lastWill) - 1);
        mqtt_lastWill[sizeof(mqtt_lastWill) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "MQTT lastWill: %s", mqtt_lastWill);
    }

    // Leer password de MQTT
    cJSON *mqtt_password_item = cJSON_GetObjectItem(mqtt, "password");
    if (mqtt_password_item != NULL && cJSON_IsString(mqtt_password_item)) {
        strncpy(mqtt_password, mqtt_password_item->valuestring, sizeof(mqtt_password) - 1);
        mqtt_password[sizeof(mqtt_password) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "MQTT password: %s", mqtt_password);
    }

    // Leer publishTopic
    cJSON *publishTopic = cJSON_GetObjectItem(mqtt, "publishTopic");
    if (publishTopic != NULL && cJSON_IsString(publishTopic)) {
        strncpy(mqtt_publishTopic, publishTopic->valuestring, sizeof(mqtt_publishTopic) - 1);
        mqtt_publishTopic[sizeof(mqtt_publishTopic) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "MQTT publishTopic: %s", mqtt_publishTopic);
    }

    // Leer qos
    cJSON *qos = cJSON_GetObjectItem(mqtt, "qos");
    if (qos != NULL && cJSON_IsNumber(qos)) {
        mqtt_qos = qos->valueint;
        ESP_LOGI(TAG, "MQTT QoS: %d", mqtt_qos);
    }

    // Leer responseTopic
    cJSON *responseTopic = cJSON_GetObjectItem(mqtt, "responseTopic");
    if (responseTopic != NULL && cJSON_IsString(responseTopic)) {
        strncpy(mqtt_responseTopic, responseTopic->valuestring, sizeof(mqtt_responseTopic) - 1);
        mqtt_responseTopic[sizeof(mqtt_responseTopic) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "MQTT responseTopic: %s", mqtt_responseTopic);
    }

    // Leer subscribeTopic
    cJSON *subscribeTopic = cJSON_GetObjectItem(mqtt, "subscribeTopic");
    if (subscribeTopic != NULL && cJSON_IsString(subscribeTopic)) {
        strncpy(mqtt_subscribeTopic, subscribeTopic->valuestring, sizeof(mqtt_subscribeTopic) - 1);
        mqtt_subscribeTopic[sizeof(mqtt_subscribeTopic) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "MQTT subscribeTopic: %s", mqtt_subscribeTopic);
    }

    // Leer url
    cJSON *url = cJSON_GetObjectItem(mqtt, "url");
    if (url != NULL && cJSON_IsString(url)) {
        strncpy(mqtt_url, url->valuestring, sizeof(mqtt_url) - 1);
        mqtt_url[sizeof(mqtt_url) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "MQTT url: %s", mqtt_url);
    }

    // Leer userName
    cJSON *userName = cJSON_GetObjectItem(mqtt, "userName");
    if (userName != NULL && cJSON_IsString(userName)) {
        strncpy(mqtt_userName, userName->valuestring, sizeof(mqtt_userName) - 1);
        mqtt_userName[sizeof(mqtt_userName) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "MQTT userName: %s", mqtt_userName);
    }

    // Leer datos de Wi-Fi
    cJSON *wifi_array = cJSON_GetObjectItem(props, "wifi");
    if (wifi_array == NULL || !cJSON_IsArray(wifi_array)) {
        ESP_LOGE(TAG, "No se encontró el arreglo 'wifi' en el JSON");
        cJSON_Delete(root);
        return;
    }

    cJSON *wifi_item = cJSON_GetArrayItem(wifi_array, 0);
    if (wifi_item == NULL || !cJSON_IsObject(wifi_item)) {
        ESP_LOGE(TAG, "No se encontró el objeto Wi-Fi en el arreglo");
        cJSON_Delete(root);
        return;
    }

    cJSON *ssid = cJSON_GetObjectItem(wifi_item, "ssid");
    if (ssid != NULL && cJSON_IsString(ssid)) {
        strncpy(WIFI_SSID, ssid->valuestring, sizeof(WIFI_SSID) - 1);
        WIFI_SSID[sizeof(WIFI_SSID) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "Wi-Fi SSID: %s", WIFI_SSID);
    }

    // Leer password de Wi-Fi
    cJSON *wifi_password_item = cJSON_GetObjectItem(wifi_item, "password");
    if (wifi_password_item != NULL && cJSON_IsString(wifi_password_item)) {
        strncpy(WIFI_PASS, wifi_password_item->valuestring, sizeof(WIFI_PASS) - 1);
        WIFI_PASS[sizeof(WIFI_PASS) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "Wi-Fi Password: %s", WIFI_PASS);
    }

    cJSON *bssid = cJSON_GetObjectItem(wifi_item, "bssid");
    if (bssid != NULL && cJSON_IsString(bssid)) {
        strncpy(wifi_bssid, bssid->valuestring, sizeof(wifi_bssid) - 1);
        wifi_bssid[sizeof(wifi_bssid) - 1] = '\0'; // Asegurar terminación nula
        ESP_LOGI(TAG, "Wi-Fi BSSID: %s", wifi_bssid);
    }

    // Liberar memoria del JSON parseado
    cJSON_Delete(root);
}

esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    static char *response_buffer = NULL;
    static int response_len = 0;

    switch (evt->event_id) {
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGI(TAG, "Header recieved: %.*s", evt->data_len, (char *)evt->data);
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
                handle_json_response(json_str);
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

esp_err_t fetch_config_from_api() 
{
    esp_http_client_config_t config = {
        .url = API_URL,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = http_event_handler,
        .timeout_ms = 5000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    esp_http_client_cleanup(client);

    ESP_LOGI("API", "HTTP GET %s", err == ESP_OK ? "successful" : esp_err_to_name(err));
    return err;
}

void app_main(void)
{

	/* start the wifi manager */
	wifi_manager_init();
	wifi_manager_start();

    // is_wifi_connected()

	while (!is_wifi_connected()) 
    {
        vTaskDelay(pdMS_TO_TICKS(500));
    }

	// TODO: If lost wifi connection per more than 10 min, start modem

	if (strcmp(DEVICE_UUID, "DEFAULT"))
	{
		get_device_uuid(DEVICE_MAC, DEVICE_TOKEN, DEVICE_TYPE);
	}

    ESP_ERROR_CHECK(fetch_config_from_api()); // get config from device

}