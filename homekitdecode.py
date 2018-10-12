#!/usr/bin/env python3
## (c) 2018 Joshua Wright
##
## Install oyaml with `pip3 install oyaml`

import sys
import oyaml as yaml # Used to preserve order of dict
import pdb

tlvtypes = {
    0x00: "kTLVType_Method",
    0x01: "kTLVType_Identifier",
    0x02: "kTLVType_Salt",
    0x03: "kTLVType_PublicKey",
    0x04: "kTLVType_Proof",
    0x05: "kTLVType_EncryptedData",
    0x06: "kTLVType_State",
    0x07: "kTLVType_Error",
    0x08: "kTLVType_RetryDelay",
    0x09: "kTLVType_Certificate",
    0x0A: "kTLVType_Signature",
    0x0B: "kTLVType_Permissions",
    0x0C: "kTLVType_FragmentD",
    0x0D: "kTLVType_FragmentLast",
    0xFF: "kTLVType_Seperator"}

tlvmethods = {
    0: "Reserved.",
    1: "Pair Setup.",
    2: "Pair Verify.",
    3: "Add Pairing.",
    4: "Remove Pairing.",
    5: "List Pairings."}

KTLV_METHOD = 0
KTLV_STATE = 6

def processhkdata(data):
    try:
        header,payload = data.split(b"\x0d\x0a\x0d\x0a")
    except ValueError:
        print("(empty data)\n")
        return

    if payload == "":
        print("(empty data)\n")
        return

    i=0
    try:
        while i < len(payload):
            ktlvtype = payload[i]
            ktlvlen = payload[i+1]
            print("Type: %d (%s), Length: %d"%(ktlvtype, tlvtypes[ktlvtype], ktlvlen))

            if (ktlvtype == KTLV_METHOD):
                    print("%s (%02x)\n"%(tlvmethods[payload[i+2]], payload[i+2]))
                    i+=i+2+ktlvlen
                    continue
            if (ktlvtype == KTLV_STATE):
                    print("M%d (%02x)\n"%(payload[i+2], payload[i+2]))
                    i+=i+2+ktlvlen
                    continue

            # Only if we didn't parse the value (e.g. data, proof, or unknown)
            for payloadbyte in range(0, ktlvlen):
                print("%02x "% payload[i+2+payloadbyte], end=""),

            print("")
            i=i+2+ktlvlen
            print("")
    except IndexError:
        print("(incomplete data)\n")
        return

if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print("Decode a Wireshark TCP Stream YAML File of HomeKit Data")
        print("(Wireshark | 'http' display filter | Follow TCP Stream | Show data as YAML | Save as file)")
        print("")
        print("%s [yaml file]"%sys.argv[0])
        sys.exit(0)

    with open(sys.argv[1],'r') as f:
        try:
            hkyaml=yaml.load(f)
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit(1)

    for key in hkyaml:
        if (key[0:5] == "peer0"):
            print(">>>> %s"%key)
        else:
            print("<<<< %s"%key)

        processhkdata(hkyaml[key])


