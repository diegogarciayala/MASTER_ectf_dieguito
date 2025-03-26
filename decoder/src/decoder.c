/**
 * @file    decoder.c
 * @brief   Implementación segura del Decoder para eCTF.
 *          Se incorpora validación de HMAC (usando wolfSSL’s wc_AesCmac) y descifrado con AES-CTR.
 * @date    2025
 *
 * NOTA: Las funciones de entrada/salida (read_packet, write_packet, print_debug, print_error, etc.)
 *       no se modifican.
 */


#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/cmac.h>  /* Se espera que esto declare wc_AesCmac */

/* Si aun no se declara wc_AesCmac, definimos un prototipo (o stub) para poder compilar.
   Nota: En una implementación real, esta función debe provenir de wolfSSL */
#ifndef WC_AESCMAC_DECLARED
int wc_AesCmac(const uint8_t *key, int keyLen, const uint8_t *data, int dataLen, uint8_t *out_mac);
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"
#include "simple_crypto.h"  /* Proporciona BLOCK_SIZE (ej.: AES_BLOCK_SIZE) */

/* Solo se definen estas macros si no han sido definidas ya por los headers del SDK */
#ifndef MXC_FLASH_MEM_BASE
    #define MXC_FLASH_MEM_BASE 0x00000000
#endif
#ifndef MXC_FLASH_MEM_SIZE
    #define MXC_FLASH_MEM_SIZE 0x00100000
#endif
#ifndef MXC_FLASH_PAGE_SIZE
    #define MXC_FLASH_PAGE_SIZE 0x00001000
#endif

#ifndef FLASH_STATUS_ADDR
    #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#endif

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF

/* Stubs para boot flag (dummy, se usan en boot_flag() pero no son necesarios en la versión final) */
static const uint32_t aseiFuengleR[] = { 0x12345678, 0 };
static const uint32_t djFIehjkklIH[] = { 0x87654321, 0 };

uint8_t deobfuscate(uint32_t a, uint32_t b) {
    return (uint8_t)(a ^ b);
}

/* Stub para crypto_example, si CRYPTO_EXAMPLE está definido */
#ifdef CRYPTO_EXAMPLE
void crypto_example(void) {
    /* Implementación vacía */
}
#endif

#pragma pack(push, 1)
typedef struct {
    uint32_t channel;
    uint64_t timestamp;
    uint8_t data[FRAME_SIZE + 8 + 16]; /* ciphertext (frame || TS) + HMAC (16B) */
} frame_packet_t;

typedef struct {
    uint32_t decoder_id;
    uint64_t start_timestamp;
    uint64_t end_timestamp;
    uint32_t channel;
    uint8_t hmac[16]; /* HMAC */
} subscription_update_packet_t;

typedef struct {
    uint32_t channel;
    uint64_t start;
    uint64_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;
#pragma pack(pop)

typedef struct {
    bool active;
    uint32_t id;
    uint64_t start_timestamp;
    uint64_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot;
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

flash_entry_t decoder_status;

/* ------------------ FUNCIONES CRIPTOGRÁFICAS ------------------ */

/* AES-CTR implementado con encrypt_sym().
   Se hace cast a (uint8_t*) en key para evitar advertencias por const. */
void aes_ctr_crypt(const uint8_t *key, const uint8_t *nonce, 
                   const uint8_t *in, uint8_t *out, uint32_t length) {
    uint8_t counter[BLOCK_SIZE];
    memcpy(counter, nonce, BLOCK_SIZE);
    uint32_t num_blocks = (length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (uint32_t i = 0; i < num_blocks; i++) {
        uint8_t keystream[BLOCK_SIZE];
        encrypt_sym(counter, BLOCK_SIZE, (uint8_t *)key, keystream);
        uint32_t block_size = (length - i * BLOCK_SIZE > BLOCK_SIZE) ? BLOCK_SIZE : (length - i * BLOCK_SIZE);
        for (uint32_t j = 0; j < block_size; j++) {
            out[i * BLOCK_SIZE + j] = in[i * BLOCK_SIZE + j] ^ keystream[j];
        }
        for (int j = BLOCK_SIZE - 1; j >= 0; j--) {
            if (++counter[j] != 0)
                break;
        }
    }
}

/* Función de CMAC usando wolfSSL.
   Se utiliza wc_AesCmac con una llave de 16 bytes. */
void aes_cmac(const uint8_t *key, const uint8_t *data, uint32_t data_len, uint8_t *out_mac) {
    if (wc_AesCmac(key, 16, data, data_len, out_mac) != 0) {
        memset(out_mac, 0, 16);
    }
}

/* ------------------ OBTENCIÓN DE CLAVES (dummy) ------------------ */
int get_channel_key(uint32_t channel, uint8_t *key_out) {
    for (int i = 0; i < 16; i++) {
        key_out[i] = (uint8_t)(channel + i);
    }
    return 0;
}

int get_K_mac(uint8_t *key_out) {
    uint8_t dummy[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
    memcpy(key_out, dummy, 16);
    return 0;
}

/* ------------------ FUNCIONES DEL DECODER ------------------ */
int is_subscribed(uint32_t channel) {
    if (channel == EMERGENCY_CHANNEL)
        return 1;
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel &&
            decoder_status.subscribed_channels[i].active)
            return 1;
    }
    return 0;
}

void compute_subscription_hmac(const subscription_update_packet_t *sub, uint8_t *out_hmac) {
    uint8_t channel_key[16];
    get_channel_key(sub->channel, channel_key);
    uint8_t data[4 + 4 + 8 + 8];
    memcpy(data, &sub->channel, 4);
    memcpy(data + 4, &sub->decoder_id, 4);
    memcpy(data + 8, &sub->start_timestamp, 8);
    memcpy(data + 16, &sub->end_timestamp, 8);
    aes_cmac(channel_key, data, sizeof(data), out_hmac);
}

int update_subscription(uint16_t pkt_len, subscription_update_packet_t *update) {
    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }
    uint8_t computed_hmac[16];
    compute_subscription_hmac(update, computed_hmac);
    if (memcmp(computed_hmac, update->hmac, 16) != 0) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - invalid HMAC\n");
        return -1;
    }
    int i;
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel ||
            !decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }
    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

int decode(uint16_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    if (pkt_len < 4 + 8 + 16) {
        print_error("Packet too short\n");
        return -1;
    }
    uint32_t channel = new_frame->channel;
    uint64_t timestamp = new_frame->timestamp;
    uint32_t ciphertext_len = pkt_len - (12 + 16);
    uint8_t *ciphertext = new_frame->data;
    uint8_t *received_hmac = new_frame->data + ciphertext_len;
    uint8_t header[12];
    memcpy(header, &channel, 4);
    memcpy(header + 4, &timestamp, 8);
    uint8_t K_mac[16];
    get_K_mac(K_mac);
    uint8_t computed_hmac[16];
    {
        uint32_t hmac_data_len = 12 + ciphertext_len;
        uint8_t *hmac_data = malloc(hmac_data_len);
        if (!hmac_data)
            return -1;
        memcpy(hmac_data, header, 12);
        memcpy(hmac_data + 12, ciphertext, ciphertext_len);
        aes_cmac(K_mac, hmac_data, hmac_data_len, computed_hmac);
        free(hmac_data);
    }
    if (memcmp(computed_hmac, received_hmac, 16) != 0) {
        STATUS_LED_RED();
        print_error("HMAC verification failed in frame\n");
        return -1;
    }
    if (!is_subscribed(channel)) {
        STATUS_LED_RED();
        sprintf(output_buf, "Receiving unsubscribed channel data. %u\n", channel);
        print_error(output_buf);
        return -1;
    }
    uint8_t channel_key[16];
    get_channel_key(channel, channel_key);
    uint8_t nonce[BLOCK_SIZE];
    memcpy(nonce, &timestamp, 8);
    memcpy(nonce + 8, &channel, 4);
    memset(nonce + 12, 0, 4);
    uint8_t *plaintext = malloc(ciphertext_len);
    if (!plaintext)
        return -1;
    aes_ctr_crypt(channel_key, nonce, ciphertext, plaintext, ciphertext_len);
    if (ciphertext_len < 8) {
        free(plaintext);
        return -1;
    }
    uint32_t frame_len = ciphertext_len - 8;
    uint64_t decrypted_ts;
    memcpy(&decrypted_ts, plaintext + frame_len, 8);
    if (decrypted_ts != timestamp) {
        STATUS_LED_RED();
        print_error("Timestamp mismatch in decrypted frame\n");
        free(plaintext);
        return -1;
    }
    write_packet(DECODE_MSG, plaintext, frame_len);
    free(plaintext);
    return 0;
}

void init() {
    int ret;
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        print_debug("First boot.  Setting flash...\n");
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        channel_status_t subscription[MAX_CHANNEL_COUNT];
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT * sizeof(channel_status_t));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        while (1)
            ;
    }
}

void boot_flag(void) {
    char flag[28];
    char output_buf[128] = {0};
    for (int i = 0; aseiFuengleR[i]; i++) {
        flag[i] = deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
        flag[i + 1] = 0;
    }
    sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
    print_debug(output_buf);
}

int list_channels() {
    list_response_t resp;
    uint16_t len;
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
    write_packet(LIST_MSG, &resp, len);
    return 0;
}

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;
    init();
    print_debug("Decoder Booted!\n");
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
#ifdef CRYPTO_EXAMPLE
            crypto_example();
#endif
            boot_flag();
            list_channels();
            break;
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
