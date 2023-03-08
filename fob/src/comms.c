/**
 * @file comms.c
 * @author Electro707 (Jamal Bouajjaj)
 * @brief Firmware UART interface implementation
 * @date 2023
 *
 * This file handles all UART communication: Between this fob and the host, and this fob and 
 *    another car/fob.
 * 
 * This module handles the encryption and decryption of each message
 */

#include <stdbool.h>
#include <stdint.h>

#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"

#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"

#include "comms.h"

#include "uart.h"
#include "aes.h"
#include "uECC.h"
#include "unewhaven_crc.h"

// NOTE NOTE: This flag should be REMOVED for submission.
// It's only here for debugging purposes
#define RUN_UNENCRYPTED

#ifdef RUN_UNENCRYPTED
#warning("Running UART unencrypted!!!")
#endif

typedef enum {
  RECEIVE_PACKET_STATE_RESET = 0,     // The device is doing nothing
  RECEIVE_PACKET_STATE_DEHC_EXCHANGED, // The device last received a DEHC public key
} RECEIVE_PACKET_STATE_e;

typedef enum {
  FOB_STATE_NORMAL_MODE,
  FOB_STATE_PARING_MODE,
}

typedef enum {
  // Paring related commands
  COMMAND_BYTE_PAIRED_IN_PAIRING_MODE = 0x10,
  COMMAND_BYTE_UNPARED_IN_PARING_MODE = 0x11,
  COMMAND_BYTE_FROM_UNPAIRED_PIN = 0x12,
  COMMAND_BYTE_TO_UNPAIRED_SECRET_ID = 0x13,
  // Feature related commands
  COMMAND_BYTE_ENABLE_FEATURE = 0x20,
  // Car unlocking locking
  COMMAND_BYTE_TO_CAR_UNLOCK = 0x30,
  // NACK commands. This wil also end the frame
  COMMAND_BYTE_TO_UNPAIRED_NACK = 0xE0,
  COMMAND_BYTE_TO_HOST_NACK = 0xE1,
  COMMAND_BYTE_TO_CAR_NACK = 0xE2,
} COMMAND_BYTE_e;

typedef struct
{
  uint8_t packet_size;    // The packet size to be received
  // The receive buffer and it's index from the host or fob.
  // NOTE: This buffer does NOT include the first packet length packet
  uint8_t buffer[256];
  uint8_t buffer_index;
  // The received bytes state (start or in middle of receiving)
  uint8_t receiving_data_flag;
  // The message frame state
  RECEIVE_PACKET_STATE_e state;
  // The AES struct context for encryption
  struct AES_ctx aes_ctx;
  uint8_t aes_key[16];
  // The ECDH public and secret keys and curve used to generate the shared key
  uint8_t ecc_public[16];
  uint8_t ecc_secret[16];
  struct uECC_Curve_t * curve;    // TODO: Maybe have one global curve
  uint32_t uart_base;
} DATA_TRANSFER_T;

DATA_TRANSFER_T host_comms;
DATA_TRANSFER_T board_comms;

void process_host_uart(DATA_TRANSFER_T *host);

/**
 * @brief Set the up board link and car link UART
 *
 * UART 0 is used to communicate between host and this fob
 * UART 1 is used to communicate between boards
 */
void setup_uart_links(void) {
  uart_init_host();
  uart_init_board();

  host_comms.curve = uECC_secp128r1();
  host_comms.uart_base = HOST_UART;

  board_comms.uart_base = UART1_BASE;
  
  // TODO: Temporary key
  memset(host_comms.aes_key, 'A', 128);

  AES_init_ctx(&host_comms.aes_ctx, host_comms.aes_key);
}


/**
 * Function that gets called when a packet is received for the host UART.
 * 
 * NOTE: Eventually switch this to interrupt
 * TODO: Make this universal for board and host list, as they will be the same
 */
void receive_host_uart(void){
  DATA_TRANSFER_T *host = &host_comms;
  uint8_t uart_char = (uint8_t)uart_readb(HOST_UART);

  if(host->receiving_data_flag == 0){
    host->packet_size = uart_char;
    if(host->packet_size == 0){
      return;
    }
    if((host->packet_size  % 16) != 0){
      return;
    }
    host->buffer_index = 0;
    host->receiving_data_flag = 1;
  }
  else{
    host->buffer[host->buffer_index++] = uart_char;
    if(--host->packet_size == 0){ // If we are on our last packet
      host->receiving_data_flag = 0;
      process_host_uart(host);
    }
  }
}

/**
 * Function to process host message only from received data
 *
 * TODO: Maybe move this to firmware.c as it relates more to the operation rather than communication
 */
void process_host_uart(DATA_TRANSFER_T *host){
  if(host->buffer_index <= 3){  // Smallest message must include at least ony byte and CRC
    // TODO: Raise error: too short
    return;
  }
  // Check CRC with the rest of the message
  uint16_t real_crc = host->buffer[host->buffer_index-1] & (host->buffer[host->buffer_index-2] << 8);
  uint16_t calc_crc = calculate_crc(host->buffer, host->buffer_index-2);
  if(calc_crc != real_crc){
    // TODO: Raise error
    return;
  }

  if(host->state == PACKET_STATE_RESET){
    if(host->buffer[0] == 0xAB){  // TODO: #define token
      // We are receiving our first packet which is a ECDH exchange
      if(host->buffer_index != 1+16+2){
        // TODO: Raise error: packet size wrong
        return;
      }
      generate_ecdh_local_keys(host);
      // NOTE: This can be a vulnerability if buffer size is not right
      uECC_shared_secret(host->buffer[1], host->ecc_secret, host->aes_key, host->curve);
      generate_and_send_message(host, TO_SEND_BACK_ECDH_PUBLIC);
      host->state = RECEIVE_PACKET_STATE_DEHC_EXCHANGED;
    }
  }

  #ifndef RUN_UNENCRYPTED
  AES_CBC_decrypt_buffer(&host->aes_ctx, host->buffer, host->buffer_index);
  #endif

  switch(host->buffer[0]){
    case COMMAND_BYTE_UNPARED_IN_PARING_MODE: // The host sent the paring command with pin, so we must be the unpaired fob
      // TODO: Check if we are the unpaired fob
      if(get_if_paired() == 0){
        generate_ecdh_local_keys(board_comms);
        generate_and_send_message(board_comms, START_ECDH_TRANSACTION);    // Start transaction with the fob
      }
      else{
        generate_and_send_message(host_comms, NACK_TO_HOST);
      }
      break;
    case COMMAND_BYTE_PAIRED_IN_PAIRING_MODE: // The host sent the pairing mode command, so we must be the paired fob
      if(get_if_paired() == 1){

      }
      else{

      }
      break;
    case COMMAND_BYTE_FROM_UNPAIRED_PIN:
      break;
  }
}

void process_other_device_uart(DATA_TRANSFER_T *host){

}

inline void generate_ecdh_local_keys(DATA_TRANSFER_T *hosts){
  uECC_make_key(hosts->ecc_public, hosts->ecc_secret, hosts->ecdh_curve);
}

/**
 * A common message generator to the host and car/fob
 */
void generate_and_send_message(DATA_TRANSFER_T *hosts, SEND_MESSAGE_TYPE to_send_type){
  static uint8_t to_send_msg[30];
  uint8_t msg_len = 0;
  switch(to_send_type){
    case TO_SEND_BACK_ECDH_PUBLIC:
      to_send_msg[1] = 0xE0;
      memcpy(hosts->ecc_public, &to_send_msg[2], 16);
      msg_len += 17;
      break;
    case TO_SEND_START_ECHD:
      to_send_msg[1] = 0xAB;
      memcpy(hosts->ecc_public, &to_send_msg[2], 16);
      msg_len += 17;
      break;

  }

  // CRC for overall message
  msg_len += 2;
  // Length of overall message
  to_send_msg[0] = msg_len;
  msg_len += 1;

  for (int i = 0; i < msg_len; i++) {
    UARTCharPut(hosts->uart_base, message->buffer[i]);
  }
}

uint32_t get_random_seed(){

}
