# Solution
Category: Forensics

Difficulty: Medium

This challenge involves analyzing a USB traffic capture to reconstruct a series of typed commands. The key is to distinguish between keyboard and mouse data, handle typos, and execute the final recovered command.

Tools Needed
Wireshark (or tshark)

Python with scapy or pyshark

A standard USB HID Scan Code table (found online)

# Procedure:

# Step 1 
When you first open typingcats.pcapng in Wireshark, you'll see a flood of UDP packets between 1.3.3.7 and 1.0.0.1. This is the first clue that the important data is inside the UDP payload.

If you inspect the packets, you'll notice the Raw payload is always exactly 8 bytes. This is the characteristic size of a USB HID report for devices like keyboards and mice.

The challenge now is to figure out which of these 8-byte payloads are keyboard strokes and which are just noise.

# Step 2
By researching the USB HID protocol, we can find the structure of these 8-byte reports.
```
Keyboard Report: [modifier_byte, 0, keycode_1, keycode_2, ...]

Mouse Report: [buttons, x_movement, y_movement, ...]
```

The key difference is the second byte. In a standard keyboard report, the second byte is reserved and is always 0x00. In our dummy mouse reports, the second byte represents X-axis movement and will almost always be non-zero.

This gives us a simple but effective Wireshark filter to isolate only the keyboard packets:

`udp.payload[1] == 00`

Applying this filter cleans up the traffic significantly, leaving a clear, chronological sequence of keystrokes.

# Step 3
While you can see the keycodes in Wireshark, the volume of packets and the use of typos make a script the most efficient way to solve the challenge.
The goal is to write a Python script that:

- Reads all packets from the PCAP file.

- Filters for packets that match our keyboard report structure (payload[1] == 0).

- Iterates through the list and parses the 8-byte payload of each packet.

- Only processes "key down" events. A "key down" is when a keycode appears in the payload (payload[2] is not zero).

- Maintains the state of the Shift key (is payload[0] equal to 0x02?).

- Translates the keycode (payload[2]) into an ASCII character.

- Builds the command string one character at a time, handling the Backspace keycode (0x2a) by removing the last character.

A successful script will process all the packets in the correct order and print the final, cleaned-up command.

# Step 4
After running the script, the fully reconstructed command will be revealed:
```
echo 'ZmxhZ3tlWGVjVVQxbmdfY21kNV8wbjNfazNZX2FUX2FfVDFtM180ZjQxMjQzODQ3ZGE2OTNhNGYzNTZjMDQ4NjExNGJjNn0=' | base64 -d
```
The final step is to copy this command, paste it into a Linux terminal, and execute it. The command runs, decodes the Base64 string, and prints the flag.

Flag: `flag{eXecUT1ng_cmd5_on3_k3Y_aT_a_T1m3_4f41243847da693a4f356c0486114bc6}`