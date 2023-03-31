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
// #define RUN_UNENCRYPTED

#ifdef RUN_UNENCRYPTED
#warning("Running UART unencrypted!!!")
#endif

DATA_TRANSFER_T host_comms;
DATA_TRANSFER_T board_comms;

// Curve for ECDH
const struct uECC_Curve_t * curve;

void generate_ecdh_local_keys(DATA_TRANSFER_T *hosts);
void process_received_packet(DATA_TRANSFER_T *host);
void receive_anything_uart(uint32_t uart_base, DATA_TRANSFER_T *host);

int get_random_bytes(uint8_t *buff, uint16_t len);

/**
 * @brief Set the up board link and car link UART
 *
 * UART 0 is used to communicate between host and this fob
 * UART 1 is used to communicate between boards
 */
void setup_uart_links(void) {
  uart_init_host();
  uart_init_board();

  curve = uECC_secp192r1();

  host_comms.uart_base = HOST_UART;
  board_comms.uart_base = BOARD_UART;
  // TODO: Have better reset mechanism
  host_comms.exchanged_ecdh = false;
  board_comms.exchanged_ecdh = false;
  
  // TODO: Temporary key
  // memset(host_comms.aes_key, 'A', 24);

  // NOTE: Not needed as the context gets generated per transaction
  // AES_init_ctx(&host_comms.aes_ctx, host_comms.aes_key);

  uECC_set_rng(get_random_bytes);

}

void receive_host_uart(void){
  receive_anything_uart(HOST_UART, &host_comms);
}

void receive_board_uart(void){
  receive_anything_uart(BOARD_UART, &board_comms);
}


/**
 * Function that gets called when a packet is received for the host UART.
 * 
 * NOTE: Eventually switch this to interrupt
 */
void receive_anything_uart(uint32_t uart_base, DATA_TRANSFER_T *host){
  uint8_t uart_char = (uint8_t)uart_readb(uart_base);

  switch(host->state){
    case RECEIVE_PACKET_STATE_RESET:
      host->packet_size = uart_char;
      if(host->packet_size < 3 || host->packet_size >= MAXIMUM_PACKET_SIZE){
        return;
      }
      host->crc = 0;
      host->buffer_index = 0;
      host->state = RECEIVE_PACKET_STATE_DATA;
      break;
    case RECEIVE_PACKET_STATE_DATA:
      host->buffer[host->buffer_index] = uart_char;
      // The case below should never occur, but handle it anyways
      if(++host->buffer_index >= MAXIMUM_DATA_BUFFER){
        // todo: handle errors gracefully
        host->state = RECEIVE_PACKET_STATE_RESET;
      }
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
  if(host->buffer_index < 3 || host->buffer_index > 80){  // Smallest message must include at least ony byte and CRC
    // TODO: Raise error: too short
    return;
  }
  // Check CRC with the rest of the message
  uint16_t calc_crc = calculate_crc(host->buffer, host->buffer_index);
  if(calc_crc != host->crc){
    // TODO: Raise error
    return;
  }

  uart_debug_number(host->buffer[0]);
  uart_debug_strln(" <- Received instruction");
  
  if(host->exchanged_ecdh == false){
    // TODO: If this is a board commands, do a sanity check whether it is right to start
    // receiving a command
    if(host->buffer[0] == COMMAND_BYTE_NEW_MESSAGE_ECDH){
      if(host->buffer_index == 1+ECDH_PUBLIC_KEY_BYTES+AES_IV_SIZE_BYTES){   // Check size, which 
        generate_ecdh_local_keys(host);
        memcpy(host->aes_iv, host->buffer+1+ECDH_PUBLIC_KEY_BYTES, AES_IV_SIZE_BYTES);
        // NOTE: This can be a vulnerability if buffer size is not right
        setup_secure_aes(host, &host->buffer[1]);
        // TODO: Might have to re-do the aes key structure
        generate_send_message(host, COMMAND_BYTE_RETURN_OWN_ECDH, host->ecc_public, ECDH_PUBLIC_KEY_BYTES);
        host->exchanged_ecdh = true;
      }
      else{
        // todo: This returns as encrypted, while not having any encryption key
        returnNack(host);
      }
    }
    else if(host->buffer[0] == COMMAND_BYTE_RETURN_OWN_ECDH && host == &board_comms){
      // TODO: Add checks around this
      process_board_uart();
    }
    else{
      returnNack(host);
    }
  }
  else{
#ifndef RUN_UNENCRYPTED
      AES_ctx_set_iv(&host->aes_ctx, &host->aes_iv);
      AES_CBC_decrypt_buffer(&host->aes_ctx, host->buffer, host->buffer_index);
#endif
    if(host == &host_comms){
      process_host_uart();
    }
    else{
      process_board_uart();
    }
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
  message_state = COMMAND_STATE_RESET;
}

void returnAck(DATA_TRANSFER_T *host){
  generate_send_message(host, COMMAND_BYTE_ACK, NULL, 0);
}

void create_new_secure_comms(DATA_TRANSFER_T *host){
  uint8_t to_send[ECDH_PUBLIC_KEY_BYTES+AES_IV_SIZE_BYTES];
  generate_ecdh_local_keys(host);
  // Generate some AES IV
  get_random_bytes(host->aes_iv, AES_IV_SIZE_BYTES);
  // Copy the right packet into `to_send`
  memcpy(to_send, host->ecc_public, ECDH_PUBLIC_KEY_BYTES);
  memcpy(to_send+ECDH_PUBLIC_KEY_BYTES, host->aes_iv, AES_IV_SIZE_BYTES);
  // Send it
  generate_send_message(host, COMMAND_BYTE_NEW_MESSAGE_ECDH, to_send, ECDH_PUBLIC_KEY_BYTES+AES_IV_SIZE_BYTES);
}

void setup_secure_aes(DATA_TRANSFER_T *host, uint8_t *other_public){
  uECC_shared_secret(other_public, host->ecc_secret, host->aes_key, curve);
  AES_init_ctx_iv(&host->aes_ctx, host->aes_key, host->aes_iv);
}

/**
 * A common message generator to the host and car/fob
 */
void generate_send_message(DATA_TRANSFER_T *host, COMMAND_BYTE_e command, uint8_t *data, uint8_t len){
  uint8_t to_send_msg[AES_BLOCKLEN*5];
  memset(to_send_msg, 0, AES_BLOCKLEN*5);
  uint8_t msg_len = 1;
  to_send_msg[1] = command;
  if(len != 0){
    memcpy(&to_send_msg[2], data, len);
    msg_len += len;
  }

  #ifndef RUN_UNENCRYPTED
  // Don't encrypt any COMMAND_BYTE_NEW_MESSAGE_ECDH or COMMAND_BYTE_RETURN_OWN_ECDH commands
  if(!(command == COMMAND_BYTE_NEW_MESSAGE_ECDH || command == COMMAND_BYTE_RETURN_OWN_ECDH)){
    if(msg_len % AES_BLOCKLEN != 0){
      msg_len += AES_BLOCKLEN-(msg_len % AES_BLOCKLEN);
    }
    AES_ctx_set_iv(&host->aes_ctx, &host->aes_iv);
    AES_CBC_encrypt_buffer(&host->aes_ctx, to_send_msg+1, msg_len);
  }
  #endif

  // CRC for overall message
  uint16_t crc = calculate_crc(&to_send_msg[1], msg_len);
  to_send_msg[1+msg_len++] = (crc >> 8) & 0xFF;
  to_send_msg[1+msg_len++] = crc & 0xFF;
  // Length of overall message
  to_send_msg[0] = msg_len;
  msg_len += 1;   // This is only for the next function
  
  uart_write(host->uart_base, to_send_msg, msg_len);
}

void uart_debug_strln(const char *str){
  uart_write(DEBUG_UART, (uint8_t *)str, strlen(str));
  uart_debug_newline();
}

void uart_debug_number(uint32_t numb){
  char reversed_str[10];
  char *reversed_str_index = reversed_str;

  const volatile char *digits = "0123456789ABCDEF";

  do
  {
    *reversed_str_index++ = digits[numb % 10];
  } while ((numb /= 10) != 0);
  
  // Reverse string
  for(reversed_str_index--;reversed_str_index >=reversed_str;reversed_str_index--){
    uart_writeb(DEBUG_UART, *reversed_str_index);
  }
}

void uart_debug_newline(void){
  uart_writeb(DEBUG_UART, '\n');
}

uint32_t get_random_seed(){
  return SysTickValueGet();
}

// Temporary function for getting random bytes
int get_random_bytes(uint8_t *buff, uint16_t len){
  do{
    *buff++ = (uint8_t)(SysTickValueGet() & 0xFF);
  }while(--len > 0);
  return 1;
}