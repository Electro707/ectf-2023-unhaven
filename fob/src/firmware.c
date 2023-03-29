/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Fob Example Design Implementation
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include "firmware.h"

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"
#include "driverlib/systick.h"

#include "secrets.h"

#include "comms.h"
#include "feature_list.h"
#include "uart.h"

#define FOB_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE         \
  (sizeof(FLASH_DATA) % 4 == 0) \
      ? sizeof(FLASH_DATA)      \
      : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))

typedef enum{
  PAIRED_STATE_PAIRED = 0xAB,
  PAIRED_STATE_UNPAIRED = 0xFF,
}PAIRED_STATE_e;

/*** Structure definitions ***/

// Defines a struct for storing the state in flash
typedef struct
{
  PAIRED_STATE_e paired;           // Wether we are paired or not
  uint8_t encrypted_pin[16];   // The hashed pin
  uint8_t car_secret[16];   // The car secret
  uint8_t feature_bitfield;
} FLASH_DATA;

COMMAND_STATE_e message_state = COMMAND_STATE_RESET;

/*** Function definitions ***/
// Core functions - all functionality supported by fob
void saveFobState(FLASH_DATA *flash_data);
void init_other_aes_context(void);

int8_t process_received_new_feature(uint8_t *data);
uint8_t get_if_paired(void);

void startUnlockCar(void);
static void sendCarUnlockToken(void);

uint8_t unpaired_received_pin[16];

struct AES_ctx feature_unlock_aes;
struct AES_ctx pin_unlock_aes;

static const uint8_t pre_programmed_pin[16] = PAIR_PIN;
static const uint8_t pre_programmer_car_secret[16] = CAR_SECRET;

FLASH_DATA fob_state_ram;

/**
 * @brief Main function for the fob example
 *
 * Listens over UART and SW1 for an unlock command. If unlock command presented,
 * attempts to unlock door. Listens over UART for pair command. If pair
 * command presented, attempts to either pair a new key, or be paired
 * based on firmware build.
 */
int main(void)
{
  FLASH_DATA *fob_state_flash = (FLASH_DATA *)FOB_STATE_PTR;

  SysTickPeriodSet(16777216);
  SysTickEnable();

// If paired fob, initialize the system information
#if PAIRED == 1
  if (fob_state_flash->paired == PAIRED_STATE_UNPAIRED)
  {
    memcpy(fob_state_ram.encrypted_pin, pre_programmed_pin, 16);
    memcpy(fob_state_ram.car_secret, pre_programmer_car_secret, 16);
    fob_state_ram.paired = PAIRED_STATE_PAIRED;
    saveFobState(&fob_state_ram);
  }
#endif

  if (fob_state_flash->paired == PAIRED_STATE_PAIRED){
    memcpy(&fob_state_ram, fob_state_flash, FLASH_DATA_SIZE);
  }

  // This will run on first boot to initialize features
  if (fob_state_ram.feature_bitfield == 0xFF)
  {
    fob_state_ram.feature_bitfield = 0;
    saveFobState(&fob_state_ram);
  }

  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  init_other_aes_context();

  // Initialize board link UART
  setup_uart_links();

  uart_init_debug();

  // Setup SW1
  GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
  GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                   GPIO_PIN_TYPE_STD_WPU);
  
  uart_debug_strln("Started Program!3\0");

  uint8_t previous_sw_state = GPIO_PIN_4;
  uint8_t debounce_sw_state = GPIO_PIN_4;
  uint8_t current_sw_state = GPIO_PIN_4;

  // Infinite loop for polling UART
  while (true)
  {
    // Non blocking UART polling
    if (uart_avail(HOST_UART)){
      receive_host_uart();
    }

    // Non blocking UART polling
    if (uart_avail(BOARD_UART)){
      receive_board_uart();
    }

    current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
    if ((current_sw_state != previous_sw_state) && (current_sw_state == 0)){
      // Debounce switch
      for (int i = 0; i < 10000; i++)
        ;
      debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
      if (debounce_sw_state == current_sw_state)
      {
        startUnlockCar();
        // unlockCar(&fob_state_ram);
        // if (receiveAck())
        // {
        //   startCar(&fob_state_ram);
        // }
      }
    }
    previous_sw_state = current_sw_state;
  }
}

void init_other_aes_context(void){
  uint8_t eeprom_stuff[24];

  EEPROMRead((uint32_t *)eeprom_stuff, 0x00, 24);
  AES_init_ctx(&feature_unlock_aes, eeprom_stuff);

  EEPROMRead((uint32_t *)eeprom_stuff, 0x20, 24);
  AES_init_ctx(&pin_unlock_aes, eeprom_stuff);
}

/**
 * Function to process host message only from received data
 */
void process_host_uart(void){
  uint8_t stat;
  DATA_TRANSFER_T *host = &host_comms;

  switch(host->buffer[0]){
    // If we are a paired fob and was just told to be in pairing mode
    case COMMAND_BYTE_PAIRED_IN_PAIRING_MODE:
      if(get_if_paired() == 1){
        // TODO: Add pairing mode state
        returnAck(host);
      }
      else{
        returnNack(host);
      }
      break;
    case COMMAND_BYTE_UNPARED_IN_PARING_MODE: // The host sent the paring command with pin, so we must be the unpaired fob
      // TODO: Check if we are the unpaired fob
      if(get_if_paired() == 0){
        // TODO: Check for received secret
        // Copy over the hashed pin to confirm with paired fob
        memcpy(unpaired_received_pin, &host->buffer[1], 16);
        // Create a secure connection with a paired fob and wait for received message
        // generate_ecdh_local_keys(&board_comms);
        // generate_standard_message(&board_comms, COMMAND_BYTE_NEW_MESSAGE_ECDH);    // Start transaction with the fob
        create_new_secure_comms(&board_comms);
        // board_comms.exchanged_ecdh == true;
        // TODO: Move the stuff above in a function in comms.c
        message_state = COMMAND_STATE_WAITING_FOR_PAIRED_ECDH;
      }
      else{
        returnNack(host);
      }
      break;
    case COMMAND_BYTE_ENABLE_FEATURE:
      // Sanity check to make sure we are paired
      if(get_if_paired() != 1){
        returnNack(host);
        break;
      }
      stat = process_received_new_feature(host->buffer);
      if(stat != 0){
        returnNack(host);
        break;
      }
      break;
    default:
      returnNack(host);
      break;
  }
}

void process_board_uart(void){
  DATA_TRANSFER_T *host = &board_comms;

  switch(host->buffer[0]){
    case COMMAND_BYTE_RETURN_OWN_ECDH:
      // This can happen either because we are a unpaired fob and just established comms with paired fob,
      // Or we are a paired fob trying to communicate with a car
      // TODO: Add general check around message_state
      if(host->buffer_index != 1+48){
        if(message_state == COMMAND_STATE_WAITING_FOR_PAIRED_ECDH){
          returnNack(&host_comms);
        }
        returnNack(host);
        break;
      }
      setup_secure_aes(host, &host->buffer[1]);
      // TODO: Initialize the internal AES context with generated key
      if(message_state == COMMAND_STATE_WAITING_FOR_PAIRED_ECDH){
        // We send out our hashed pairing key in order to get the secret
        // TODO: Add check
        generate_send_message(host, COMMAND_BYTE_GET_SECRET, unpaired_received_pin, 16);
      }
      else if(message_state == COMMAND_STATE_WAITING_FOR_CAR_ECDH){
        sendCarUnlockToken();
        // For now the fob does nothing about any return statement, so do nothing...
        host->exchanged_ecdh = false;
        message_state = COMMAND_STATE_RESET;
      }
      else{
        returnNack(host);
        break;
      }
      break;
    case COMMAND_BYTE_GET_SECRET:
      // If we are are a paired pin and the unpaired pin wants the secrets
      // Do a sanity check to determine if we are the right devices
      if(get_if_paired() != 1){
        returnNack(host);
        break;
      }
      if(memcmp(fob_state_ram.encrypted_pin, host->buffer+1, 16)){
        // We now need to send the secrets to the unpaired fob
        generate_send_message(host, COMMAND_BYTE_RETURN_SECRET, fob_state_ram.car_secret, 16);
      }
      else{
        returnNack(host);
      }
      break;
    case COMMAND_BYTE_RETURN_SECRET:
      // If we are the unpaired fob and we just got our secret, yay
      message_state = COMMAND_STATE_RESET;
        host->exchanged_ecdh = false;
      if(get_if_paired() != 0){
        // We send a NACK back to the host
        returnNack(&host_comms);
        // host->exchanged_ecdh = false;
        break;
      }
      // TODO: Store this in FLASH
      memcpy(fob_state_ram.encrypted_pin, unpaired_received_pin, 16);
      memcpy(fob_state_ram.car_secret, &host->buffer[1], 16);
      fob_state_ram.paired = true;
      saveFobState(&fob_state_ram);
      returnAck(&host_comms);
      // host->exchanged_ecdh = false;
      break;
    case COMMAND_BYTE_NACK:
      // I mean there isn't much to do here, other than reset
      host->exchanged_ecdh = false;
      message_state = COMMAND_STATE_RESET;
      break;
    default:
      // TODO: Do something, probably
      break;
  }
}

int8_t process_received_new_feature(uint8_t *data){
  uint8_t feature_number;

  AES_CBC_decrypt_buffer(&feature_unlock_aes, data, 32);
  // if(memcmp(data+0, CAR_ID, 6) != 0){
    // return -1;
  // }
  if(memcmp(data+6, fob_state_ram.encrypted_pin, 16) != 0){
    return -1;
  }
  feature_number = *(data+6+16);
  // TODO: Maybe add a check around the feature_number number
  fob_state_ram.feature_bitfield |= (1 << feature_number);
  saveFobState(&fob_state_ram);
  return 0;
}

/**
 * Function that gets called when a button is pressed, to mainly unlock the car
*/
void startUnlockCar(void){
  if(get_if_paired() != 1){
    uart_debug_strln("Not Paired");
    return;
  }
  if(message_state != COMMAND_STATE_RESET){
    uart_debug_strln("Not in comm reset");
    return;
  }
  // Start ECDH with car
  uart_debug_strln("Unlocking Car!!");
  create_new_secure_comms(&board_comms);
  message_state = COMMAND_STATE_WAITING_FOR_CAR_ECDH;
}

/**
 * This gets called when the car returns the ECDH exchange
*/
static void sendCarUnlockToken(void){
  // Let's pack the car secret and feature bits
  uint8_t to_send[16+1];
  memcpy(to_send, fob_state_ram.car_secret, 16);
  to_send[16] = fob_state_ram.feature_bitfield;
  generate_send_message(&board_comms, COMMAND_BYTE_TO_CAR_UNLOCK, to_send, 17);
}

/**
 * @brief Function that erases and rewrites the non-volatile data to flash
 *
 * @param info Pointer to the flash data ram
 */
void saveFobState(FLASH_DATA *flash_data)
{
  FlashErase(FOB_STATE_PTR);
  FlashProgram((uint32_t *)flash_data, FOB_STATE_PTR, FLASH_DATA_SIZE);
}

uint8_t get_if_paired(void){
  return fob_state_ram.paired == PAIRED_STATE_PAIRED;
}
