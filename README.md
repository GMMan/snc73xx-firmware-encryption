Sonix SNC73xx Firmware Encryption
=================================

The SNC73xx series of microcontrollers (including the SNC7320 and SNC7330/7340
lines) support firmware encryption.

## Boot process

To understand what information is needed for encrypted boot, we need to first
look at the boot process. The bootrom scans for a structure called the load
table from a supported boot medium. It is typically 512 bytes in size and
located at the beginning of the boot device. For SPI NOR flash boot, it also
scans in a zigzag pattern between the start and end of flash for supporting user
bootloader scenarios. A load table identifies itself by starting with one of the
following strings: `SNC7320`, `SN323200`, `SNUR00`, `SN98300`, `SONIXDEV`, and
for SPI NAND media, `SNCSPINF`.

There are two versions of the load table. To identify which version, read the
word (32-bit, little-endian) at offset +0x1fc of the table. Value `0x5a5a0002`
indicates a load table for SNC7320, while a value of `0x5a5a0033` indicates a
load table for SNC7330/SNC7340 (hereafter referred to as just SNC7330 because
the bootrom is the same between both series). We will refer to the table for
SNC7320 as V2 and the one for SNC7330 as V3. SNC7330 can handle V2 load tables
to a degree.

After the table is read, the bootrom first checks for whether priority boot is
enabled, and scans through priority boot devices if it is. This allows the usage
of load tables on a different boot device for upgrade and recovery purposes.
Priority boot is not available when booting from SD card, and cannot be nested.
For whichever load table is ultimately picked, there is a manual load table
address which can be specified to redirect to another load table (which also
supports priority boot, if the original table was not found during priority boot
scanning).

After the final load table is selected, the bootrom will load (and decrypt if
necessary) the main code into PRAM. If the load table is V2, additional sections
specified in the manual load table will be loaded (and decrypted if necessary).
For load table V3, additional SRAM code and deep power down (DPD) code will be
loaded (and decrypted) if specified. As implemented, additional load is only
supported when booting from SPI NOR flash, and DPD code is ignored.

After all code has been loaded, the bootrom will either perform a software reset
into the user application, or jump to it, depending on flag values.

## SPI NOR flash load table scanning

In order to support firmware layout that includes bootloaders, in SPI NOR flash
boot the load table is scanned for in a zigzag pattern. It starts from the start
of flash at 0x0, then 0x1000. Subsequently, it starts from double the address
from the end of flash, then the same offset from the start of flash, and so on
until the address goes out of flash range. E.g. 0x0, 0x1000, -0x2000, 0x2000,
-0x4000, 0x4000, -0x8000, 0x8000, etc.


## Encryption keys

The load table stores some flags at offset +0x8. The least significant bit
indicates the firmware code is encrypted if set. The firmware will be decrypted
if the flag is set. For V3, at offset +0x80 if the encryption trigger mark
`0x5f5f4e45` (`EN__`) is set, the firmware is pending encryption and will be
encrypted during next boot.

At offset +0x28 is the 32-byte key material. This key is used for IV derivation
and AES cryptography operations.

An additional "device key" is required to generate the final IV for decryption.
This key is a 16- or 32-bit value stored within the microcontroller's eFuses.
16-bit values are zero-extended to 32 bits.

## Encryption logic

Firmware decryption is performed by the microcontroller's AES peripheral. A
critical detail is the peripheral generally works with all data in reverse
order. Keys, IVs, and blocks all use a bytewise reversed order compared to
standard AES implementations.

To derive the IV, the first 16 bytes of the AES key is XORed with the device
key. The XOR is applied as a word over each of the four words of the IV
material. The IV material is then encrypted in ECB mode using the last 16 bytes
of the AES key as the encryption key.

After IV derivation, the full 32-byte AES key is used. In V2, the firmware is
processed using OFB mode, while in V3 it is processed using CBC mode.

In OFB mode, the IV is encrypted before it is XORed against the current block
(in reverse byte order as previously mentioned). The process repeats with the
resulting IV from the previous block encrypted again and applied to the current
block.

In CBC mode, the current block is decrypted, then the IV XORed with the
decrypted data, and encrypted block becomes the next block's IV. In CBC mode,
the IV is reset to the original derived IV every 0x1000 bytes.

Both OFB mode and CBC mode are implemented as expected, aside from the reversed
blocks and IV compared to standard AES.

Only full multiples of blocks are processed. A partial block at the end will not
be decrypted. For V3, all decrypted data must be a multiple of block size to be
successfully automatically encrypted.

## Load table details

Only fields relevant to code loading are included

### Load table

<table><thead>
  <tr>
    <th>Offset</th>
    <th>Name</th>
    <th>Type</th>
    <th>Description</th>
  </tr></thead>
<tbody>
  <tr>
    <td>0x0</td>
    <td><code>MARK</code></td>
    <td><code>char[8]</code></td>
    <td>Load table identifier</td>
  </tr>
  <tr>
    <td>0x8</td>
    <td><code>LOAD_CFG</code></td>
    <td><code>uint32_t</code></td>
    <td>Packed struct; notable fields (hex value is mask):
      <ul>
        <li><code>0x00000001</code> <code>ENCRYPTED_BOOT_CODE</code>: whether boot code is encrypted</li>
        <li><code>0x00000002</code> <code>CHECK_BOOT_CODE</code>: CRC checks are performed</li>
        <li><code>0x0fff0000</code> <code>MULTIBOOT_MSK</code>: priority boot enabled if value is <code>0xfff</code></li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>0x10</td>
    <td><code>ADDR_USERCODE</code></td>
    <td><code>uint32_t</code></td>
    <td>Address of code to load to PRAM; can be XIP address (e.g. starting from
    <code>0x60000000</code> for SPI NOR flash)</td>
  </tr>
  <tr>
    <td>0x14</td>
    <td><code>SIZE_USERCODE</code></td>
    <td><code>uint32_t</code></td>
    <td>Size of code to load to PRAM</td>
  </tr>
  <tr>
    <td>0x24</td>
    <td><code>CRC_CHK_SUM</code></td>
    <td><code>uint32_t</code></td>
    <td>CRC of code to load to PRAM</td>
  </tr>
  <tr>
    <td>0x28</td>
    <td><code>AES_KEY</code></td>
    <td><code>uint32_t[8]</code></td>
    <td>AES-256 encryption key</td>
  </tr>
  <tr>
    <td>0x68</td>
    <td><code>MANUAL_TABLE_ADDR</code></td>
    <td><code>uint32_t</code></td>
    <td>Manual load table address for SPI NOR boot; requires valid XIP address
    if used</td>
  </tr>
  <tr>
    <td>0x80</td>
    <td><code>ENCRYPTER</code></td>
    <td><code>Encrypter_t</code></td>
    <td>Encrypter configuration, V3-only</td>
  </tr>
  <tr>
    <td>0xc0</td>
    <td><code>BOOT_PRIORITY</code></td>
    <td><code>vb_pri_boot_t[4]</code></td>
    <td>Priority boot table</td>
  </tr>
  <tr>
    <td>0x140</td>
    <td><code>MANUAL_LOAD_num</code></td>
    <td><code>uint32_t</code></td>
    <td>Number of manual load entries</td>
  </tr>
  <tr>
    <td>0x144</td>
    <td><code>MANUAL_LOAD_sec</code></td>
    <td><code>load_sec_t[10]</code></td>
    <td>Manual load entries, V2-only</td>
  </tr>
  <tr>
    <td>0x1f8</td>
    <td><code>TABLE_VERSION</code></td>
    <td><code>uint32_t</code></td>
    <td>Load table version</td>
  </tr>
  <tr>
    <td>0x1fc</td>
    <td><code>TABLE_CHK_SUM</code></td>
    <td><code>uint32_t</code></td>
    <td>
      Load table checksum; additive word checksum over previous data<br>
      <em>Note:</em> Does not have to be correct; bootrom will read load table a
      second time to confirm contents if checksum is incorrect, and ignore
      checksum if content matches
    </td>
  </tr>
</tbody>
</table>

### Encrypter configuration

V3-only

| Offset | Name             | Type         | Description                                                             |
|--------|------------------|--------------|-------------------------------------------------------------------------|
| 0x0    | `MARK`           | `uint8_t[4]` | Encryption mark; if `EN__`, firmware will be encrypted during next boot |
| 0x4    | `CRC_SUM_EXT`    | `uint32_t`   | SRAM code CRC checksum                                                  |
| 0x8    | `CRC_SUM_DPD`    | `uint32_t`   | DPD code CRC checksum                                                   |
| 0x10   | `ADDR_SRAM_CODE` | `uint32_t`   | SRAM code address                                                       |
| 0x14   | `SIZE_SRAM_CODE` | `uint32_t`   | SRAM code size                                                          |
| 0x18   | `ADDR_DPD_CODE`  | `uint32_t`   | DPD code address                                                        |
| 0x1c   | `SIZE_DPD_CODE`  | `uint32_t`   | DPD code size                                                           |

SRAM code is loaded only when booting from SPI NOR flash. DPD code is ignored by
bootrom.

Note attempting to encrypt code when not booting from SPI NOR flash will likely
result in data corruption or boot failure if SPI NOR flash is attached.

### Priority boot entry

Each entry is 32 bytes

<table><thead>
  <tr>
    <th>Offset</th>
    <th>Name</th>
    <th>Type</th>
    <th>Description</th>
  </tr></thead>
<tbody>
  <tr>
    <td>0x0</td>
    <td><code>DEVICE</code></td>
    <td><code>uint32_t</code></td>
    <td>
      Device type
      <ul>
        <li><code>0x01</code>: SPI NOR flash</li>
        <li><code>0x02</code>: SD card 1</li>
        <li><code>0x04</code>: NAND flash</li>
        <li><code>0x08</code>: SPI NAND flash</li>
        <li><code>0x10</code>: SD card 0</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>0x4</td>
    <td><code>ADDR</code></td>
    <td><code>dev_addr_t</code></td>
    <td>Address value, 28 bytes; first member is <code>uint32_t</code> of
      address or offset in device/file; if SD card, file path of up to 24
      characters follow</td>
  </tr>
</tbody>
</table>

### Manual load entry

V2-only, each entry is 16 bytes

| Offset | Name           | Type       | Description                                               |
|--------|----------------|------------|-----------------------------------------------------------|
| 0x0    | `DES_ADDR`     | `uint32_t` | Destination address in RAM                                |
| 0x4    | `SRC_ADDR`     | `uint32_t` | Source address or offset in device/file                   |
| 0x8    | `SIZE`         | `uint32_t` | Size of data; if encrypted, must be no larger than 32 KiB |
| 0xc    | `CRC_CHECKSUM` | `uint32_t` | CRC checksum of data                                      |

## CRC checksums

If CRC checks are enabled, decrypted data is checked. If the checksum fails, the
boot iteration fails.

### CRC32 parameters

Standard CRC32 parameters

- Polynomial: `0xedb88320`
- Reflection: yes
- Initial value: `0xffffffff`
- Final XOR: `0xffffffff`

---

# Recovering the device key

The attached program takes a firmware image and outputs potential device key
candidates. Provide path to firmware image as the argument. Your system must
support AES-NI to use this program.

If you have a modern system, the process should be fairly fast. The program
finished in around 10 seconds on a 10th-gen Intel Core i7 laptop CPU.

## Output format

Each candidate results from a start of vector table that appears valid when the
start of program code is decrypted using material derived from the candidate
device key.

```
<device key candidate>: <initial SP> <reset handler> <NMI handler> <hard fault handler>
```

## Interpreting candidates

The candidates have been prefiltered for valid SP alignment, function addresses
in Thumb mode, and all addresses being located in valid memory regions for the
SNC73xx series. You can further filter the results yourself with some other
criteria specific to your target device:

- Limit initial SP to the range of your device's SRAM size; the SP should also
  be near the top of the SRAM
- If there is no PSRAM, filter out handlers in the `0x3xxxxxxx` range
- Handler addresses should be favored in this order: PRAM, I-cache, XIP flash
- Cap any direct XIP addresses to the amount of SPI NOR flash actually attached

By applying additional filtering, you may be able to narrow down to a single
candidate.

---

# Is this encryption scheme secure?

Of course not. These people are not very good at cryptography. Let's enumerate
some of the problems.

- AES key stored in plaintext: this almost entirely defeats the scheme in CBC
  mode. In CBC mode, the encrypted block becomes the IV for each subsequent
  block, which means you can decrypt everything except the first block. With a
  chunk repeat of 0x1000 bytes, this means 99.6% of the encrypted data can be
  recovered without knowing the device key.
- Short key length: since the AES key is stored in plaintext, the only secret
  left is the device key stored in eFuses. Without access to the device that
  encrypted the data, there is only 32 bits of secrecy. On some devices, it's as
  low as 16 bits. This is all easily brute-forceable on modern hardware.
- eFuses not protected: if you do happen to have access to the device, the
  bootrom enables SWD and a UART console by default if there is no valid
  firmware, and on SNC7300, boot can be interrupted through UART or test mode
  sequence. The eFuses are directly readable through SWD or the UART console,
  easily revealing the last bit of secrecy.
- Non-unique keys: the AES key tends to be left at the default of all zeroes on
  SNC7330 or `0x11111111 0x22222222 ...` on SNC7320. The IV is deterministically
  generated instead of uniquely generated per device while encrypting. Even the
  device key is apparently the same across each batch of chips. This means when
  one firmware has been compromised, all devices of the same manufacturing batch
  is compromised.
- No authentication: there is no signing of any sort, and no root of trust.
  Standard AES does not prove integrity. Modifying bits of the ciphertext may
  allow manipulation of the plaintext, and CRC checking can be disabled by
  flipping a flag in the header. The bootrom also doesn't enforce the load table
  checksum, not that it's signed in any way either.
- Failed attempt to protect sensitive logic/data: On SNC7330, there is a hidden
  portion of the bootrom that contains the code loading logic, including the
  encryption/decryption logic. Unfortunately, the protection is toggled on by a
  couple of instructions, and they are easily neutralized by debug facilities
  built into the CPU core. On SNC7320 the encryption logic is not protected at
  all, which allows some insights to be gained into SNC7330's process because of
  how similar the two device series are. Additionally, the AES peripheral is not
  disabled after completing its usage, revealing configuration state. It even
  allows key readback. Despite attempts to protect the key when used for
  decryption, the AES peripheral can itself be used to decrypt the masked key.
  This is where it is really apparent that the designers of this chip knows
  nothing about making secure hardware.

Overall, just security theater. It's not real encryption, and even as DRM to
bind firmware to specific devices, it fails pretty hard by not having unique
secrets per device.
