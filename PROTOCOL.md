# ECTF 2023 UNewHaven Protocol
This document gives an overview of the protcol used in this ECTF 2023 competition.

## Frame
Each message will be packed in a frame. Each frame will have the following format (exceptions are noted):

| Packet Size (1 byte) | Data ( n bytes in 16 byte chunks) | CRC (2 bytes)

- The packet size is bounded between 3 and x packets
- The packet size includes the CRC
- Data will be in 16 byte chunks except where specified. unused data shall be padded with random data
    - NOTE: ^^ See about implementation
- The data is ALWAYS encrypted with the shared AES key (more on that later) except when noted

## Sizes
- AES Block Size: 16 bytes
- AES IV Size: 128 bites (16 bytes)
- AES Key Size: 192 bytes (24 bytes)
- ECDH Size: 192 bytes (24 bytes)
- ECDH Public Key: 48 bytes

## Secrets
The following secrets will be flashed per fob:
- **Feature Encryption Key**: A key to decryption a feature data
- **Pin Encryption Key**: A key that is used to encrypte a pin, which is how it's stored internally to the fob

The following secrets will be flashed per car and fob pair:
- **Car Unlock Secret (16 bytes)**: A secret key that is used to authenticate a fob

## Packet Definition
Here are the different data packets possible in this system.
Shown is only the data porting of a frame

| Name                              | Data Structure                                                    | Notes                                                                     |
|-----------------------------------|-------------------------------------------------------------------|---------------------------------------------------------------------------|
| Establish Channel                 | `0xAB` > ECHD Public Key (48 bytes) > AES Start IV (16 bytes)     | The data is NOT ENCRYPTED && Data does not need to be in 16 byte chunks   |
| Establish Channel Return          | `0xE0` > ECHD Public Key (48 bytes)                               | The data is NOT ENCRYPTED && Data does not need to be in 16 byte chunks   |
| Set Paired fob in Pairing Mode    | `0x4D`                                                            |                                                                           |
| Set Unpaired Fob to Pair          | `0x50` > Hashed Pin (28 bytes)                                    | This call will have the unpaired fob start communication with paired fob  |
| Get Secret from Paired            | `0x47` > Encrypted Pin (32 bytes)                                 |                                                                           |
| Return Secret from Paired         | `0x52` > Car Unlock Secret Key (16 bytes)                         |                                                                           |
| ACK                               | `0x41`                                                            |                                                                           |
| NACK                              | `0xAA`                                                            |                                                                           |
| Enable Feature                    | `0x45` > Encrypted Feature data (48 bytes)                        |                                                                           |
| Unlock Car                        | `0x55` > Car Unlock Secret (16 bytes) > Feature Bitfield (1 byte) |                                                                           |
| Unlocked Car Message              | _64-bits + (64-bits * feature_enabled)_                           | This is an EEPROM memory dump of a specific location as per the rules     |

## Pin
The pin, a 6-digit string, will be taken and hashed with BLAKE2 which will be called "Hashed Pin".

### Encrypted Pin
When transmitting the pin between fobs, the pin will be further encrypted with a pre-set decryption key.

## Feature Data
The un-encrypted feature data is defined as follows:

Car ID (6 bytes) > Encrypted Pin (32 bytes) > Feature Number (1 byte, 0 to 3)

This data is padded to 48 bytes, then is encrypted with a Feature Encryption Key that is unique and stored per-fob

## Transactions
The following section describes the different possible transactions

Here are the naming abreviation:
- U -> Unpaired Fob
- P -> Paired Fob
- H -> Host

### Pair Fob Process
|---|     |---|
|   |<--->| P |<---\
|   |     |---|    |
| H |              |
|   |     |---|    |
|   |<--->| U |<---/
|---|     |---|

#### Packet Sequence
1.  H -> P => `Establish Channel`
2.  P -> H => `Establish Channel Return`
3.  H -> P => `Set Paired fob in Pairing Mode`
4.  P -> H => `ACK`
5.  H -> U => `Establish Channel`
6.  U -> H => `Establish Channel Return`
7.  H -> U => `Set Unpaired Fob to Pair`
8.  U -> P => `Establish Channel`
9.  P -> U => `Establish Channel Return`
10. U -> P => `Get Secret from Paired`
11. P -> U => `Return Secret from Paired`
12. U -> H => `ACK`

## Enable Feature
|---|     |---|
| H |<--->| P |
|---|     |---|

#### Packet Sequence
1.  H -> P => `Establish Channel`
2.  P -> H => `Establish Channel Return`
3.  H -> P => `Enable Feature`
4.  P -> H => `ACK`

## Unlock Car

|---|     |---|     |---|
| H |<--->| C |<--->| P |
|---|     |---|     |---|

#### Packet Sequence
1. P -> C => `Establish Channel`
2. C -> P => `Establish Channel Return`
3. P -> C => `Unlock Car`
4. C -> H => `Unlocked Car Message`
