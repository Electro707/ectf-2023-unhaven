#!/usr/bin/python3 -u

# @file gen_secret
# @author Jake Grycel
# @brief Example script to generate header containing secrets for the fob
# @date 2023
#
# This source file is part of an example system for MITRE's 2023 Embedded CTF (eCTF).
# This code is being provided only for educational purposes for the 2023 MITRE eCTF
# competition, and may not meet MITRE standards for quality. Use this code at your
# own risk!
#
# @copyright Copyright (c) 2023 The MITRE Corporation

import json
import argparse
from pathlib import Path
import hashlib 


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--header-file", type=Path)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    if args.paired:
        # Open the secret file, get the car's secret
        with open(args.secret_file, "r") as fp:
            secrets = json.load(fp)
            car_secret = secrets[str(args.car_id)+"_secret_str"]
        
        hashed_pin = hashlib.md5(args.pair_pin.encode('utf-8')).digest()
        hashed_pin_str = "["
        for h in hashed_pin:
            hashed_pin_str += f"{h:d},"
        hashed_pin_str = hashed_pin_str[:-1] + "]"

        with open(args.secret_file, "r") as fp:
            secrets = json.load(fp)
            feature_unlock = secrets["feature_unlock_key_str"]

        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 1\n")
            fp.write(f'#define PAIR_PIN "{hashed_pin_str}"\n')
            fp.write(f'#define CAR_ID "{args.car_id}"\n')
            fp.write(f'#define FEATURE_UNLOCK_KEY "{feature_unlock}"\n')
            # NOTE: This car secret is already in a nice string format
            fp.write(f'#define CAR_SECRET "{car_secret}"\n\n')
            fp.write("#endif\n")
    else:
        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 0\n")
            fp.write('#define PAIR_PIN "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]"\n')
            fp.write('#define FEATURE_UNLOCK_KEY "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]"\n')
            fp.write('#define CAR_ID "000000"\n')
            fp.write('#define CAR_SECRET "000000"\n\n')
            fp.write("#endif\n")


if __name__ == "__main__":
    main()
