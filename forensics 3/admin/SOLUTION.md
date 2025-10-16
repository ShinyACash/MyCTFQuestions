# Solution
Category: Forensics

Difficulty: Medium

The journey starts with a single file: cat_drive.img.

The Wall: The first move for any forensics player is to try the standard tools.

`mount`: Fails. No known filesystem.

`fdisk -l` Fails. No recognizable partition table.

`binwalk` / `photorec`: Fails. No standard file signatures found.
This is the first gate. It proves we're dealing with something custom.

The Hex Editor: The only option left is to go low-level. We open cat_drive.img in a hex editor (like bless, HxD, or 010 Editor). At first, it looks like random noise.

After scrolling, we spot a repeating pattern: the 4-byte sequence CA 7F 00 0D, but this is also very hard to spot unless taken clues from the description. This is our anchor. It's a magic number marking the beginning of a data structure. But what does it mean?

An experienced player knows that multi-byte numbers are often stored in little-endian format, meaning the byte order is reversed in the file. To get the actual number, we need to flip the bytes:
`CA 7F 00 0D` -> becomes the number -> `0x0D007FCA`

`CA7F000D` literally says "catfoood" with an extra 'o'. The description also has a clear hint about "hunger" lol.

The player has to make the connection that 0x0D007FCA is a clever hexspeak representation of "CAT FOOD." This confirms our theory about the block structure and gives us the magic number to search for. Now all we need to do is put this into the solve.py script and boom.

The flag is typed in as chunks in `secret.txt` which upon joining gives us: `flag{i_l0v3_c4rs_iF_y0u_c4nT_T3ll_bY_n0w_6669eff3224f704745a755de8d3a1e54}`