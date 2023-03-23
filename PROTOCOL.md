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

## Packet Definition
Here are the different data packets possible in this system.
Shown is only the data porting of a frame

| Name                              | Data Structure                                                | Notes                                                                     |
|-----------------------------------|---------------------------------------------------------------|---------------------------------------------------------------------------|
| Establish Channel                 | `0xAB` > ECHD Public Key (24 bytes) > AES Start IV (16 bytes) | The data is NOT ENCRYPTED && Data does not need to be in 16 byte chunks   |
| Establish Channel Return          | `0xE0` > ECHD Public Key (24 bytes)                           | The data is NOT ENCRYPTED && Data does not need to be in 16 byte chunks   |
| Set Paired fob in Pairing Mode    | `0x4D`                                                        |                                                                           |
| Set Unpaired Fob to Pair          | `0x50` > Hashed Pin (16 bytes)                                |                                                                           |
| Get Secret from Paired            | `0x47` > Hashed Pin (16 bytes)                                |                                                                           |
| Return Secret from Paired         | `0x52` > Car Secret Key (16 bytes)                            |                                                                           |
| ACK                               | `0x41`                                                        |                                                                           |
| NACK                              | `0xAA`                                                        |                                                                           |

## Transactions
The following section describes the different possible transactions

Here are the naming abreviation:
- U -> Unpaired Fob
- P -> Paired Fob
- H -> Host

### Pair Fob Process
#### Wiring
The host will be wired to both the paired and unpaired fob. The unpaired and paired fob will also be connected togther.

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