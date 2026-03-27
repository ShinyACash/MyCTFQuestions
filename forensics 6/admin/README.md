# Solution

1. Initial Analysis

The player starts with a 1GB memory dump (plan_paris.raw) and needs to figure out what kind of OS they are working with.
Using `strings plan_paris.raw | grep "Linux version"` they will find out that the OS being used is Ubuntu 6.8.0-106-generic for which they need to generate a symbol table or find one online.

2. Setting up the Environment

Since the kernel is very specific, the player must first generate or find the symbol table.
Step: Use dwarf2json with the correct kernel headers to create a Volatility 3 symbol JSON.
Command: python3 vol.py -f plan_paris.raw linux.pslist

3. Finding the right Process

Looking at the process list, one entry stands out:
Process Name: [kworker/u2:1-ev]
Suspicion: While it looks like a kernel thread (indicated by the brackets), it has a PID that doesn't match standard kernel thread patterns, or it shows up in linux.pslist when real kernel threads usually don't.

4. Following the Paper Trail

The player investigates the open files of that suspicious PID.
Command: `python3 vol.py -f plan_paris.raw linux.lsof --pid <PID>`
Discovery: The process has an open file handle to /dev/shm/.plan_paris.txt (deleted).

5. Extracting the Loot

Since the file is deleted but open in RAM, the player must dump the memory segments of that process or use the linux.elks plugin to recover the deleted file's content.
Recovery: The content reveals a string of Hex values: 0x530x460x520x430x650x32...

6. Decoding 

The player must decode the "layers":
Layer 1 (Hex to ASCII): Translates the hex string into a Base64 string: SFRCe24zdjNy...
Layer 2 (Base64 to Plaintext): Translates the string into the final flag.

Flag: HTB{n3v3r_trU5t_c4rs_w1th_th3_m1nT_k3y5}