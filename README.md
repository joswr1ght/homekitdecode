# HomeKit Decode Script

A quick script to decode HomeKit data.

To use this script, open up a HomeKit exchange packet capture in Wireshark. Apply a display filter for `http`, then
right-click and select **Follow | TCP Stream**. Change the _Show data as_ field to **YAML**. Click **Save as...**
to export the HTTP data as a YAML file. Then run the `homekitdecode.py` script.

```
$ pip3 install oyaml
$ python3 homekitdecode.py wireshark-homekit.yaml
>>>> peer0_0
Type: 0 (kTLVType_Method), Length: 1
Pair Setup. (01)

Type: 6 (kTLVType_State), Length: 1
M1 (01)

<<<< peer1_0
(empty data)

<<<< peer1_1
Type: 6 (kTLVType_State), Length: 1
M2 (02)

Type: 3 (kTLVType_PublicKey), Length: 255
d7 c6 90 3f ea b3 40 cb 58 97 f4 d5 ab e3 1b 41 ee 99 ea 15 af ee c4 63 1c 11 ...

Type: 3 (kTLVType_PublicKey), Length: 129
e5 b5 c5 2e cf f7 26 ac 25 af 42 c6 df 40 7c 6d 52 20 2f 9b fa 78 c6 1e 05 30 ...

Type: 2 (kTLVType_Salt), Length: 16
ea 95 b8 b4 3b 05 54 b6 e6 fe 97 aa 76 8a d7 e3

>>>> peer0_1
Type: 6 (kTLVType_State), Length: 1
M3 (03)
```


