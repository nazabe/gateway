/*
    @brief Entry point for the ESP32 application.
*/

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

#include "secrets.h"

char *DEVICE_UUID = "DEFAULT";
char *DEVICE_MAC = "TOKEN_NOT_RECIVED";
char *DEVICE_TOKEN = "TOKEN_NOT_RECIVED";

/* @brief tag used for ESP serial console messages */
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

int get_device_uuid(uuid, token) {

    char request_data[256];
    snprintf(request_data, sizeof(request_data), 
             "{\"uuid\":\"%s\",\"device_type\":\"%s\",\"ssid\":\"%s\",\"password\":\"%s\",\"token\":\"%s\"}", 
             uuid, device_type, wifi_ssid, wifi_password, token); // TODO: Add 

    esp_http_client_config_t config = {
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
		get_device_uuid(DEVICE_MAC, DEVICE_TOKEN);
	}

}