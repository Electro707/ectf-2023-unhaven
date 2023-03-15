#!/usr/bin/python3 -u

import random
import json
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-file", type=Path, required=True)
    args = parser.parse_args()

    # Open the secret file if it exists
    if args.secret_file.exists():
        with open(args.secret_file, "r") as fp:
            secrets = json.load(fp)
    else:
        secrets = {}

    feature_unlock = random.randint(0, 2**(16*8))
    feature_unlock = feature_unlock.to_bytes(16, 'big')
    feature_unlock_str = "["
    for c in feature_unlock:
        feature_unlock_str += f"{c:d},"
    feature_unlock_str = feature_unlock_str[:-1] + "]"

    secrets["feature_unlock_key"] = str(feature_unlock)
    secrets["feature_unlock_key_str"] = feature_unlock_str

    with open(args.secret_file, "w") as fp:
        json.dump(secrets, fp, indent=4)

if __name__ == "__main__":
    main()