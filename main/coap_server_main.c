
#include <string.h>

/* FreeRTOS includes */
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

/* ESP includes */
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

/* Included to set hostname */
#include "tcpip_adapter.h"

/* CoAP includes */
#include "coap.h"

/* WiFi defines */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define WIFI_SSID "BELL003"
#define WIFI_PASS "qwert12345"
#define DEVICE_HOSTNAME "ESPArdu"
#define MAX_RETRY 5

/* CoAP defines */
#define COAP_LOGGING_LEVEL 0

/* FreeRTOS event group */
static EventGroupHandle_t s_wifi_event_group;
// static EventGroupHandle_t s_coap_event_group;

static const char *TAG = "esp8266_coap_server";

static char espressif_data[100];
static int espressif_data_len = 0;

static int s_retry_num = 0;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
  if (event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
    if (s_retry_num < MAX_RETRY) {
      esp_wifi_connect();
      s_retry_num++;
      ESP_LOGI(TAG, "retry connection");
    } else {
      xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
      ESP_LOGI(TAG, "connection to AP failed");
    }
  } else if (event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "assigned IP address: %s", ip4addr_ntoa(&event->ip_info.ip));
    s_retry_num = 0;
    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
  } else {
    if (event_base == WIFI_EVENT) {
      ESP_LOGI(TAG, "WIFI_EVENT %d", event_id);
    } else if (event_base == IP_EVENT) {
      ESP_LOGI(TAG, "IP_EVENT %d", event_id);
    } else {
      ESP_LOGI(TAG, "Unknown event %d in WiFi event handler", event_id);
    }
  }
}

static void get(coap_context_t *ctx, coap_resource_t *resource,
                coap_session_t *session, coap_pdu_t *request,
                coap_binary_t *token, coap_string_t *query,
                coap_pdu_t *response) {
  coap_add_data_blocked_response(
      resource, session, request, response, token, COAP_MEDIATYPE_TEXT_PLAIN, 0,
      (size_t)espressif_data_len, (const u_char *)espressif_data);
}

static void put(coap_context_t *ctx, coap_resource_t *resource,
                coap_session_t *session, coap_pdu_t *request,
                coap_binary_t *token, coap_string_t *query,
                coap_pdu_t *response) {}

static void delete (coap_context_t *ctx, coap_resource_t *resource,
                    coap_session_t *session, coap_pdu_t *request,
                    coap_binary_t *token, coap_string_t *query,
                    coap_pdu_t *response) {}

static int coap_cfg_mcast_ipv4(int sock, char *group_name) { return ESP_OK; }

static void coap_server_thread(void *p) {
  coap_context_t *ctx = NULL;
  coap_address_t serv_addr;
  coap_resource_t *resource = NULL;

  snprintf(espressif_data, sizeof(espressif_data), "no data");
  espressif_data_len = strlen(espressif_data);
  coap_set_log_level(COAP_LOGGING_LEVEL);

  while (1) {
    coap_endpoint_t *ep_udp = NULL;
    // coap_endpoint_t *ep_tcp = NULL;
    unsigned wait_ms;

    ctx = coap_new_context(NULL);
    if (!ctx) {
      continue;
    }

    /* Prepare CoAP server */
    coap_address_init(&serv_addr);
    serv_addr.addr.sin.sin_family = AF_INET;
    serv_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;
    serv_addr.addr.sin.sin_port = htons(COAP_DEFAULT_PORT);

    /* Add IPv4 enpoint */
    ep_udp = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_UDP);
    if (!ep_udp) {
      goto clean_up;
    }
    coap_cfg_mcast_ipv4(ep_udp->sock.fd, CONFIG_TARGET_MULTICAST_IPV4);

    /* Add resource */
    resource = coap_resource_init(coap_make_str_const("Test"), 0);
    if (!resource) {
      goto clean_up;
    }

    /* Register CoAP method handlers */
    coap_register_handler(resource, COAP_REQUEST_GET, get);
    coap_register_handler(resource, COAP_REQUEST_PUT, put);
    coap_register_handler(resource, COAP_REQUEST_DELETE, delete);

    /* Observe GETs */
    coap_resource_set_get_observable(resource, 1);
    coap_add_resource(ctx, resource);

    wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

    while (1) {
      int ret = coap_run_once(ctx, wait_ms);
      if (ret < 0) {
        break;
      } else if (ret && (unsigned)ret < wait_ms) {
        /* Decrement if there is a return val wait time */
        wait_ms -= ret;
      }
      if (ret) {
        wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
      }
    }
  }

clean_up:
  coap_free_context(ctx);
  coap_cleanup();

  vTaskDelete(NULL);
}

static void init_wifi(void) {
  s_wifi_event_group = xEventGroupCreate();

  tcpip_adapter_init();
  tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, DEVICE_HOSTNAME);

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                             &wifi_event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                             &wifi_event_handler, NULL));

  wifi_config_t wifi_config = {
      .sta = {.ssid = WIFI_SSID, .password = WIFI_PASS},
  };

  if (strlen((char *)wifi_config.sta.password)) {
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  }

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_LOGI(TAG, "Wifi initialized");

  /* Wait for connection success or failure */
  EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                         WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                         pdFALSE, pdFALSE, portMAX_DELAY);

  switch (bits) {
    case WIFI_CONNECTED_BIT:
      ESP_LOGI(TAG, "Connected to %s", WIFI_SSID);
      break;
    case WIFI_FAIL_BIT:
      ESP_LOGI(TAG, "Connection to %s failed", WIFI_SSID);
      break;
    default:
      ESP_LOGE(TAG, "UNEXPECTED WIFI EVENT");
  }

  ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                               &wifi_event_handler));
  ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               &wifi_event_handler));
  vEventGroupDelete(s_wifi_event_group);
}

void app_main(void) {
  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  init_wifi();

  xTaskCreate(coap_server_thread, "coap_server", 1024 * 5, NULL, 5, NULL);
}
