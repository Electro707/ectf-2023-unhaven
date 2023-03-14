/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Car Example Design Implementation
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

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

#include "secrets.h"

#include "comms.h"
#include "feature_list.h"
#include "uart.h"

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

#define NUM_FEATURES 3
#define FEATURE_END 0x7C0
#define FEATURE_SIZE 64

/*** Function definitions ***/
// Core functions - unlockCar and startCar
int8_t unlockCar(char *msg);

// Declare password
const uint8_t car_id[16] = CAR_ID;

/**
 * @brief Main function for the car example
 *
 * Initializes the RF module and waits for a successful unlock attempt.
 * If successful prints out the unlock flag.
 */
int main(void) {
  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Initialize board link UART
  setup_uart_links();

  while (true) {
    if (uart_avail(BOARD_UART)){
      receive_board_uart();
    }
  }
}

void process_board_uart(void){
  int8_t stat;
  DATA_TRANSFER_T *host = &board_comms;

  switch(host->buffer[0]){
    // This is car. Other than ECDH, this is the only command that can be used
    case COMMAND_BYTE_TO_CAR_UNLOCK:
      if(host->buffer_index != 1+16){
        returnNack(host);
        break;
      }
      stat = unlockCar(&host->buffer[1])
      if(stat != 0){
        returnHostNack();
      }
      host->exchanged_ecdh = false;
      break;
    default:
      returnAck(host);
      host->exchanged_ecdh = false;
      break;
  }
}

/**
 * This function gets called when we want to unlock car
 */
int8_t unlockCar(char *msg){
  // Check if Car ID matches
  if(memcmp(msg, car_id, 16) != 0){
    return -1;
  }
  uint8_t feature_bits = msg[16];
  // At this point we are good to unlock
  uint8_t eeprom_message[64];
  uint32_t offset;
  // Read last 64B of EEPROM
  EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
              UNLOCK_EEPROM_SIZE);

  uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

  for(uint8_t i=0;i<NUM_FEATURES;i++){
    if((feature_bits & (1<<i)) != 0){
      offset = (i+1) * FEATURE_SIZE;
      EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset, FEATURE_SIZE);
      uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
    }
  }
}