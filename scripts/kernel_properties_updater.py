#!/usr/bin/env python

"""
This script receives the paths to the kernel source directory, and the vscode c_cpp_properties.json
file.
It then extracts the macro definitions from the autoconf.h file, which were generated by the kernel
configuration.
The script then adds these macro definitions to the c_cpp_properties.json file, so that the VSCode
intellisense can use them to provide code completion and other features.
"""

import argparse
import json
import os
import sys


def _parse_args():
    arg_parser = argparse.ArgumentParser(
        description="Insert macro definition configured linux kernel for VSCode configuration."
    )
    arg_parser.add_argument(
        "-k",
        "--kernel-path",
        action="store",
        required=True,
        help="Specify kernel path. Need configured properly",
    )
    arg_parser.add_argument(
        "-f",
        "--file",
        action="store",
        required=True,
        help="c_cpp_properties.json for VSCode",
    )

    return arg_parser.parse_args()


def main():
    """
    Main function
    """
    args = _parse_args()

    autoconf_path = os.path.join(args.kernel_path, "include/generated/autoconf.h")

    if not os.path.exists(autoconf_path):
        sys.exit(f"autoconf.h doesn't exist in {autoconf_path}")
    elif not os.path.exists(args.file):
        sys.exit(f"{args.file} doesn't exist")

    defines = set()
    with open(autoconf_path, encoding="ascii") as fp:
        for raw_line in fp.readlines():
            if not raw_line.startswith("#define"):
                continue

            slines = raw_line.split()
            defines.add(f"{slines[1]}={slines[2]}")

    with open(args.file, encoding="ascii") as fp:
        properties = json.load(fp)

        for conf in properties["configurations"]:
            if "defines" in conf.keys():
                defines.update(conf["defines"])
                conf["defines"] = sorted(list(defines))

    with open(args.file, "w", encoding="ascii") as fp:
        json.dump(properties, fp, indent=4)

    print(f"Set {len(defines)} macros")


if __name__ == "__main__":
    main()
