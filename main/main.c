// Standard C libraries
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

// FreeRTOS
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// ESP-IDF logging and system
#include "esp_log.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_sntp.h"
#include "esp_heap_caps.h"
#include "esp_crt_bundle.h"

#include <stdio.h>
#include <string.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_system.h>
#include <esp_log.h>
#include <lwip/ip4_addr.h>

#include "esp_system.h"
#include "esp_mac.h"
#include "wifi_manager.h"

#include "esp_http_client.h"

#include "secrets.h"

// TODO: Use docker to fix python & idf problems

char *DEVICE_UUID = "DEFAULT";
char *DEVICE_MAC = "TOKEN_NOT_RECIVED"; // TODO: Put here real MAC
char *DEVICE_TOKEN = "TOKEN_NOT_RECIVED"; // TODO: TOKEN has not to be hardcoded
char *DEVICE_TYPE = "GATEWAY";

static const char TAG[] = "main";

bool is_wifi_connected()
{
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
    {
        return true;
    }
    return false;
}

int get_device_uuid(DEVICE_MAC, DEVICE_TOKEN, DEVICE_TYPE) {

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

    esp_err_t err = esp_http_client_perform(client);
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

void app_main(void)
{

	/* start the wifi manager */
	wifi_manager_init();
	wifi_manager_start();

	while (!is_wifi_connected()) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }

	// TODO: If lost wifi connection per more than 10 min, start modem

	if (strcmp(DEVICE_UUID, "DEFAULT"))
	{
		get_device_uuid(DEVICE_MAC, DEVICE_TOKEN, DEVICE_TYPE);
	}

}