/**
 * @file    decoder.c
 * @brief   Secure Decoder Implementation for eCTF
 */

 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 #include <wolfssl/wolfcrypt/aes.h>
 #include <wolfssl/wolfcrypt/hmac.h>
 #include <wolfssl/wolfcrypt/random.h>
 
 #include "mxc_device.h"
 #include "status_led.h"
 #include "board.h"
 #include "mxc_delay.h"
 #include "simple_flash.h"
 #include "host_messaging.h"
 #include "simple_uart.h"
 
 /* Definiciones para las claves */
 // Nota: En un sistema real, estas claves deberían estar en un header protegido o provenir de una fuente segura
 // Usando valores de ejemplo para las claves (32 bytes/256 bits cada una)
 #define MASTER_KEY_BASE64 {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
 #define MAC_KEY_BASE64 {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, \
                        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F}
 #define CHANNEL_KEY_1 {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, \
                       0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F}
 #define CHANNEL_KEY_2 {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, \
                       0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F}
 #define CHANNEL_KEY_3 {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, \
                       0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F}
 #define CHANNEL_KEY_4 {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, \
                       0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF}
 #define CHANNEL_KEY_5 {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, \
                       0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF}
 #define CHANNEL_KEY_6 {0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, \
                       0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}
 #define CHANNEL_KEY_7 {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, \
                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}
 #define CHANNEL_KEY_8 {0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, \
                       0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA}
 
 /* Definitions for types and constants */
 #define MAX_CHANNEL_COUNT 8
 #define EMERGENCY_CHANNEL 0
 #define FRAME_SIZE 64
 #define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
 #define FLASH_FIRST_BOOT 0xDEADBEEF
 #define HMAC_SIZE 32
 #define NONCE_SIZE 20
 #define KEY_SIZE 32
 
 #define timestamp_t uint64_t
 #define channel_id_t uint32_t
 #define decoder_id_t uint32_t
 #define pkt_len_t uint16_t
 
 /* Calculate the flash address for channel info */
 #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
 
 #pragma pack(push, 1)
 typedef struct {
     channel_id_t channel;
     timestamp_t timestamp;
     uint8_t encrypted_frame[FRAME_SIZE];
     uint8_t mac[HMAC_SIZE];
     uint64_t seq_num;
 } secure_frame_packet_t;
 
 typedef struct {
     channel_id_t channel;
     decoder_id_t decoder_id;
     timestamp_t start_timestamp;
     timestamp_t end_timestamp;
     uint8_t hmac[HMAC_SIZE];
 } secure_subscription_update_packet_t;
 
 typedef struct {
     uint8_t master_key[KEY_SIZE];
     uint8_t channel_keys[MAX_CHANNEL_COUNT][KEY_SIZE];
     uint8_t mac_key[KEY_SIZE];
 } secure_secrets_t;
 
 typedef struct {
     bool active;
     channel_id_t id;
     timestamp_t start_timestamp;
     timestamp_t end_timestamp;
     uint64_t last_seq_num;
 } secure_channel_status_t;
 
 typedef struct {
     uint32_t first_boot;
     secure_channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
     secure_secrets_t secrets;
 } secure_flash_entry_t;
 #pragma pack(pop)
 
 /* Definiciones para listar canales */
 #pragma pack(push, 1)
 typedef struct {
     channel_id_t channel;
     timestamp_t start;
     timestamp_t end;
 } channel_info_t;
 
 typedef struct {
     uint32_t n_channels;
     channel_info_t channel_info[MAX_CHANNEL_COUNT];
 } list_response_t;
 #pragma pack(pop)
 
 secure_flash_entry_t decoder_status;
 WC_RNG rng;
 
 int verify_subscription_hmac(secure_subscription_update_packet_t *update) {
     Hmac hmac;
     uint8_t computed_hmac[HMAC_SIZE];
     
     wc_HmacInit(&hmac, NULL, INVALID_DEVID);
     wc_HmacSetKey(&hmac, SHA256, decoder_status.secrets.mac_key, KEY_SIZE);
     wc_HmacUpdate(&hmac, (uint8_t*)update, sizeof(secure_subscription_update_packet_t) - HMAC_SIZE);
     wc_HmacFinal(&hmac, computed_hmac);
     
     return (memcmp(computed_hmac, update->hmac, HMAC_SIZE) == 0);
 }
 
 int is_subscribed(channel_id_t channel, timestamp_t timestamp) {
     if (channel == EMERGENCY_CHANNEL) return 1;
     
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == channel && 
             decoder_status.subscribed_channels[i].active &&
             timestamp >= decoder_status.subscribed_channels[i].start_timestamp &&
             timestamp <= decoder_status.subscribed_channels[i].end_timestamp) {
             return 1;
         }
     }
     return 0;
 }
 
 int update_subscription(pkt_len_t pkt_len, secure_subscription_update_packet_t *update) {
     if (update->channel == EMERGENCY_CHANNEL) {
         STATUS_LED_RED();
         print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
         return -1;
     }
     
     if (!verify_subscription_hmac(update)) {
         STATUS_LED_RED();
         print_error("Subscription HMAC verification failed\n");
         return -1;
     }
     
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == update->channel || 
             !decoder_status.subscribed_channels[i].active) {
             decoder_status.subscribed_channels[i].active = true;
             decoder_status.subscribed_channels[i].id = update->channel;
             decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
             decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
             decoder_status.subscribed_channels[i].last_seq_num = 0;
             break;
         }
     }
     
     flash_simple_erase_page(FLASH_STATUS_ADDR);
     flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(secure_flash_entry_t));
     
     write_packet(SUBSCRIBE_MSG, NULL, 0);
     return 0;
 }
 
 int decode(pkt_len_t pkt_len, secure_frame_packet_t *new_frame) {
     Hmac hmac;
     Aes aes;
     uint8_t computed_mac[HMAC_SIZE];
     uint8_t decrypted_frame[FRAME_SIZE];
     uint8_t nonce[NONCE_SIZE];
     uint8_t *channel_key;
     
     // Verify channel subscription and timestamp
     if (!is_subscribed(new_frame->channel, new_frame->timestamp)) {
         STATUS_LED_RED();
         print_error("Unsubscribed channel or invalid timestamp\n");
         return -1;
     }
     
     // Verify MAC
     wc_HmacInit(&hmac, NULL, INVALID_DEVID);
     wc_HmacSetKey(&hmac, SHA256, decoder_status.secrets.mac_key, KEY_SIZE);
     wc_HmacUpdate(&hmac, (uint8_t*)new_frame, sizeof(secure_frame_packet_t) - HMAC_SIZE);
     wc_HmacFinal(&hmac, computed_mac);
     
     if (memcmp(computed_mac, new_frame->mac, HMAC_SIZE) != 0) {
         STATUS_LED_RED();
         print_error("Frame MAC verification failed\n");
         return -1;
     }
     
     // Check sequence number to prevent replay
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == new_frame->channel) {
             if (new_frame->seq_num <= decoder_status.subscribed_channels[i].last_seq_num) {
                 STATUS_LED_RED();
                 print_error("Replay attack detected\n");
                 return -1;
             }
             decoder_status.subscribed_channels[i].last_seq_num = new_frame->seq_num;
             break;
         }
     }
     
     // Select channel key (emergency or specific channel)
     channel_key = (new_frame->channel == EMERGENCY_CHANNEL) ? 
          decoder_status.secrets.master_key : 
          decoder_status.secrets.channel_keys[new_frame->channel - 1];
     
     // Prepare nonce
     memcpy(nonce, &new_frame->channel, sizeof(channel_id_t));
     memcpy(nonce + sizeof(channel_id_t), &new_frame->timestamp, sizeof(timestamp_t));
     memcpy(nonce + sizeof(channel_id_t) + sizeof(timestamp_t), &new_frame->seq_num, sizeof(uint64_t));
     
     // Decrypt frame
     wc_AesInit(&aes, NULL, INVALID_DEVID);
     wc_AesSetKey(&aes, channel_key, KEY_SIZE, nonce, AES_ENCRYPTION);
     // Reemplazando wc_AesCtrEncrypt con wc_AesCbcEncrypt
     wc_AesCbcEncrypt(&aes, decrypted_frame, new_frame->encrypted_frame, FRAME_SIZE);
     wc_AesFree(&aes);
     
     // Write decrypted frame
     write_packet(DECODE_MSG, decrypted_frame, FRAME_SIZE);
     return 0;
 }
 
 int list_channels() {
     list_response_t resp;
     pkt_len_t len;
  
     resp.n_channels = 0;
  
     for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].active) {
             resp.channel_info[resp.n_channels].channel = decoder_status.subscribed_channels[i].id;
             resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
             resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
             resp.n_channels++;
         }
     }
  
     len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);
  
     // Success message
     write_packet(LIST_MSG, &resp, len);
     return 0;
 }
 
 void init() {
     int ret;
     uint8_t master_key[KEY_SIZE] = MASTER_KEY_BASE64;
     uint8_t mac_key[KEY_SIZE] = MAC_KEY_BASE64;
     uint8_t channel_key_1[KEY_SIZE] = CHANNEL_KEY_1;
     uint8_t channel_key_2[KEY_SIZE] = CHANNEL_KEY_2;
     uint8_t channel_key_3[KEY_SIZE] = CHANNEL_KEY_3;
     uint8_t channel_key_4[KEY_SIZE] = CHANNEL_KEY_4;
     uint8_t channel_key_5[KEY_SIZE] = CHANNEL_KEY_5;
     uint8_t channel_key_6[KEY_SIZE] = CHANNEL_KEY_6;
     uint8_t channel_key_7[KEY_SIZE] = CHANNEL_KEY_7;
     uint8_t channel_key_8[KEY_SIZE] = CHANNEL_KEY_8;
     
     // Initialize WolfSSL RNG
     wc_InitRng(&rng);
     
     flash_simple_init();
     
     flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(secure_flash_entry_t));
     if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
         decoder_status.first_boot = FLASH_FIRST_BOOT;
         
         // Initialize channel statuses
         memset(decoder_status.subscribed_channels, 0, sizeof(decoder_status.subscribed_channels));
         
         // Zero out secrets
         memset(&decoder_status.secrets, 0, sizeof(secure_secrets_t));
         
         /* En un sistema real se debe decodificar la cadena Base64 para obtener los bytes.
            Usando valores predefinidos para este ejemplo */
         memcpy(decoder_status.secrets.master_key, master_key, KEY_SIZE);
         memcpy(decoder_status.secrets.mac_key, mac_key, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[0], channel_key_1, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[1], channel_key_2, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[2], channel_key_3, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[3], channel_key_4, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[4], channel_key_5, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[5], channel_key_6, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[6], channel_key_7, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[7], channel_key_8, KEY_SIZE);
         
         flash_simple_erase_page(FLASH_STATUS_ADDR);
         flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(secure_flash_entry_t));
     }
     
     ret = uart_init();
     if (ret < 0) {
         STATUS_LED_ERROR();
         while (1);
     }
 }
 
 int main(void) {
     uint8_t uart_buf[sizeof(secure_frame_packet_t)];
     msg_type_t cmd;
     int result;
     uint16_t pkt_len;
     
     init();
     
     print_debug("Secure Decoder Booted!\n");
     
     while (1) {
         print_debug("Ready\n");
         STATUS_LED_GREEN();
         
         result = read_packet(&cmd, uart_buf, &pkt_len);
         if (result < 0) {
             STATUS_LED_ERROR();
             print_error("Failed to receive cmd from host\n");
             continue;
         }
         
         switch (cmd) {
         case LIST_MSG:
             STATUS_LED_CYAN();
             list_channels();
             break;
         case DECODE_MSG:
             STATUS_LED_PURPLE();
             decode(pkt_len, (secure_frame_packet_t *)uart_buf);
             break;
         case SUBSCRIBE_MSG:
             STATUS_LED_YELLOW();
             update_subscription(pkt_len, (secure_subscription_update_packet_t *)uart_buf);
             break;
         default:
             STATUS_LED_ERROR();
             print_error("Invalid Command\n");
             break;
         }
     }
 }