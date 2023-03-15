/**
 * @file board_link.h
 * @author Frederich Stine
 * @brief Firmware UART interface implementation.
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"

#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"
#include "driverlib/systick.h"

#include "comms.h"
#include "uart.h"
#include "aes.h"
#include "uECC.h"
#include "unewhaven_crc.h"
#include "firmware.h"

// NOTE NOTE: This flag should be REMOVED for submission.
// It's only here for debugging purposes
#define RUN_UNENCRYPTED

#ifdef RUN_UNENCRYPTED
#warning("Running UART unencrypted!!!")
#endif

DATA_TRANSFER_T board_comms;

// Curve for ECDH
const struct uECC_Curve_t * curve;

void generate_ecdh_local_keys(DATA_TRANSFER_T *hosts);
void process_received_packet(DATA_TRANSFER_T *host);
void receive_anything_uart(uint32_t uart_base, DATA_TRANSFER_T *host);

void setup_uart_links(void) {
  uart_init_host();
  uart_init_board();

  curve = uECC_secp192r1();

  board_comms.uart_base = UART1_BASE;
  // TODO: Have better reset mechanism
  board_comms.exchanged_ecdh = false;
}

/**
 * Function that gets called when a packet is received for the host UART.
 * 
 * NOTE: Eventually switch this to interrupt
 */
void receive_board_uart(void){
  DATA_TRANSFER_T *host = &board_comms;
  uint8_t uart_char = (uint8_t)uart_readb(BOARD_UART);

  switch(host->state){
    case RECEIVE_PACKET_STATE_RESET:
      host->packet_size = uart_char;
      if(host->packet_size == 0){
        return;
      }
      if((host->packet_size  % 16) != 0){
        return;
      }
      host->buffer_index = 0;
      host->state = RECEIVE_PACKET_STATE_DATA;
      break;
    case RECEIVE_PACKET_STATE_DATA:
      host->buffer[host->buffer_index++] = uart_char;
      if(--host->packet_size == 2){ // If we are on our last packet
        host->state = RECEIVE_PACKET_STATE_CRC;
      }
      break;
    case RECEIVE_PACKET_STATE_CRC:
      host->crc <<= 8;
      host->crc |= uart_char;
      if(--host->packet_size == 0){ // If we are on our last packet
        host->state = RECEIVE_PACKET_STATE_RESET;
        process_received_packet(host);
      }
      break;
    default:
      break;
  }
}

/**
 * Function that processes any received packet, whether from host or fob or car, as the 
 * underlaying communication protocol is the same.
*/
void process_received_packet(DATA_TRANSFER_T *host){
  if(host->buffer_index <= 3){  // Smallest message must include at least ony byte and CRC
    // TODO: Raise error: too short
    return;
  }
  // Check CRC with the rest of the message
  uint16_t calc_crc = calculate_crc(host->buffer, host->buffer_index);
  if(calc_crc != host->crc){
    // TODO: Raise error
    return;
  }
  
  if(host->exchanged_ecdh == false){
    // TODO: We are a car. We are to receive command
    if(host->buffer[0] == COMMAND_BYTE_NEW_MESSAGE_ECDH){
      if(host->buffer_index != 1+AES_KEY_SIZE_BYTES){
        generate_ecdh_local_keys(host);
        // NOTE: This can be a vulnerability if buffer size is not right
        setup_secure_aes(host, &host->buffer[1]);
        // TODO: Might have to re-do the aes key structure
        generate_send_message(host, COMMAND_BYTE_RETURN_OWN_ECDH, host->ecc_public, AES_KEY_SIZE_BYTES);
        host->exchanged_ecdh = true;
      }
      else{
        returnNack(host);
      }
    }
    else{
      returnNack(host);
    }
  }
  else{
#ifndef RUN_UNENCRYPTED
      AES_CBC_decrypt_buffer(&host->aes_ctx, host->buffer, host->buffer_index);
#endif
    process_board_uart();
  }

}

void generate_ecdh_local_keys(DATA_TRANSFER_T *hosts){
  uECC_make_key(hosts->ecc_public, hosts->ecc_secret, curve);
}

/**
 * Function that returns a NACK and also ends any messaging
*/
void returnNack(DATA_TRANSFER_T *host){
  generate_send_message(host, COMMAND_BYTE_NACK, NULL, 0);
  host->exchanged_ecdh = false;
}

void returnAck(DATA_TRANSFER_T *host){
  generate_send_message(host, COMMAND_BYTE_ACK, NULL, 0);
}

void create_new_secure_comms(DATA_TRANSFER_T *host){
  generate_ecdh_local_keys(host);
  generate_send_message(host, COMMAND_BYTE_NEW_MESSAGE_ECDH, host->ecc_public, AES_KEY_SIZE_BYTES);
}

void setup_secure_aes(DATA_TRANSFER_T *host, uint8_t *other_public){
  uECC_shared_secret(other_public, host->ecc_secret, host->aes_key, curve);
  AES_init_ctx(&host->aes_ctx, host->aes_key);
}

void returnHostNack(void){
  static const uint8_t *host_ack = "Car is not happy :(\n\0";
  uart_write(HOST_UART, host_ack, sizeof(host_ack));
}

/**
 * A common message generator to the host and car/fob
 */
void generate_send_message(DATA_TRANSFER_T *host, COMMAND_BYTE_e command, uint8_t *data, uint8_t len){
  static uint8_t to_send_msg[AES_KEY_SIZE_BYTES*2];
  memset(to_send_msg, 0, AES_KEY_SIZE_BYTES*2);
  uint8_t msg_len = 1;
  to_send_msg[1] = command;
  if(len != 0){
    memcpy(&to_send_msg[2], data, len);
  }

  #ifndef RUN_UNENCRYPTED
  // Don't encrypt any COMMAND_BYTE_NEW_MESSAGE_ECDH or COMMAND_BYTE_RETURN_OWN_ECDH commands
  if(!(command == COMMAND_BYTE_NEW_MESSAGE_ECDH || command == COMMAND_BYTE_RETURN_OWN_ECDH)){
    if(msg_len % AES_KEY_SIZE_BYTES != 0){
      msg_len += AES_KEY_SIZE_BYTES-(msg_len % AES_KEY_SIZE_BYTES);
    }
    AES_ECB_encrypt(&host->aes_ctx, to_send_msg, msg_len);
  }
  #endif

  // CRC for overall message
  uint16_t crc = calculate_crc(&to_send_msg[1], msg_len);
  to_send_msg[msg_len++] = (crc >> 8) & 0xFF;
  to_send_msg[msg_len++] = crc & 0xFF;
  // Length of overall message
  to_send_msg[0] = msg_len;
  msg_len += 1;   // This is only for the next function

  uart_write(host->uart_base, to_send_msg, msg_len);
}

uint32_t get_random_seed(){
  return SysTickValueGet();
}