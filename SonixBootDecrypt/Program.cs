// See https://aka.ms/new-console-template for more information
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

const uint SPI_FLASH_ADDR = 0x60000000;
const uint LOAD_TABLE_MAGIC = 0x5a5a0000;
const uint LOAD_TABLE_V2 = 0x5a5a0002;
const uint LOAD_TABLE_V3 = 0x5a5a0033;
const uint ENCRYPTER_PENDING_MARK = 0x5f5f4e45; // "EN__" for auto encrypt
const int SPI_LOAD_TABLE_SIZE = 0x200;
string[] LOAD_TABLE_MAGIC_VALUES = [
    "SNC7320",
    "SN323200",
    "SNUR00",
    "SN98300",
    "SONIXDEV",
    "SNCSPINF",
];

byte[] ReverseArray(byte[] input)
{
    input = (byte[])input.Clone();
    Array.Reverse(input);
    return input;
}

bool IsLoadTableWithEncryption(BinaryReader br, uint baseOffset)
{
    br.BaseStream.Seek(baseOffset, SeekOrigin.Begin);
    byte[] tableMagic = br.ReadBytes(8);

    bool match = false;
    foreach (var value in LOAD_TABLE_MAGIC_VALUES)
    {
        match = true;
        for (int i = 0; i < value.Length; ++i)
        {
            if (tableMagic[i] != value[i])
            {
                match = false;
                break;
            }
        }

        if (match)
        {
            break;
        }
    }

    if (!match) return false;

    // ENCRYPTED_BOOT_CODE flag check
    br.BaseStream.Seek(baseOffset + 8, SeekOrigin.Begin);
    uint loadCfg = br.ReadUInt32();
    if ((loadCfg & 1) == 0) return false;

    br.BaseStream.Seek(baseOffset + 0x1f8, SeekOrigin.Begin);
    uint tableVersion = br.ReadUInt32();
    if ((tableVersion & 0xffff0000) != LOAD_TABLE_MAGIC) return false;

    // ENCRYPTER.MARK check (not currently encrypted if present)
    if (tableVersion >= LOAD_TABLE_V3)
    {
        br.BaseStream.Seek(baseOffset + 0x80, SeekOrigin.Begin);
        uint mark = br.ReadUInt32();
        if (mark == ENCRYPTER_PENDING_MARK)
        {
            return false;
        }
    }

    // Validate data is in flash
    br.BaseStream.Seek(baseOffset + 0x10, SeekOrigin.Begin);
    uint userCodeAddr = br.ReadUInt32();
    int userCodeLength = br.ReadInt32();
    if (userCodeAddr < SPI_FLASH_ADDR || userCodeAddr + userCodeLength > SPI_FLASH_ADDR + 0x10000000)
        return false;

    return true;
}

if (args.Length != 1)
{
    Console.Error.WriteLine($"Usage: {Environment.GetCommandLineArgs()[0]} <inPath>");
    return 1;
}

try
{
    using FileStream fs = File.OpenRead(args[0]);
    BinaryReader br = new(fs);

    // Locate load table
    uint offset = 0;
    bool fromEnd = false;
    bool loadTableFound = false;
    while (!loadTableFound && offset < fs.Length / 2)
    {
        if (!fromEnd)
        {
            if (offset + SPI_LOAD_TABLE_SIZE <= fs.Length)
            {
                loadTableFound = IsLoadTableWithEncryption(br, offset);
            }
            else
            {
                break;
            }
        }
        else
        {
            offset *= 2;
            if (fs.Length - offset >= 0)
            {
                loadTableFound = IsLoadTableWithEncryption(br, (uint)(fs.Length - offset));
            }
            else
            {
                break;
            }
        }

        if (loadTableFound) break;

        if (offset == 0)
        {
            offset = 0x1000;
        }
        else
        {
            fromEnd = !fromEnd;
        }
    }

    if (!loadTableFound)
    {
        Console.Error.WriteLine("Could not locate load table with encrypted data.");
        return 3;
    }

    // Read encryption candidate
    fs.Seek(offset + 0x10, SeekOrigin.Begin);
    uint userCodeAddr = br.ReadUInt32();
    fs.Seek(userCodeAddr - SPI_FLASH_ADDR, SeekOrigin.Begin);
    byte[] encrypted = br.ReadBytes(16);

    // Key setup
    fs.Seek(offset + 0x28, SeekOrigin.Begin);
    byte[] inKey = br.ReadBytes(32);
    Array.Reverse(inKey);

    // Read load table version
    br.BaseStream.Seek(offset + 0x1f8, SeekOrigin.Begin);
    uint tableVersion = br.ReadUInt32();

    CipherMode aesMode = tableVersion switch
    {
        < LOAD_TABLE_V3 => CipherMode.OFB,
        >= LOAD_TABLE_V3 => CipherMode.CBC,
    };

    // Setup AES
    KeyParameter keyParameterRound = new KeyParameter(inKey);
    KeyParameter keyParameterIv = new KeyParameter(inKey.AsSpan(0, 0x10).ToArray());
    byte[] ivMaterial = inKey.AsSpan(0x10, 0x10).ToArray();

    // Precalculate some stuff for hot path
    byte[] cbcPrecalculated;
    Span<uint> baseUIntSpan;
    switch (aesMode)
    {
        case CipherMode.OFB:
            baseUIntSpan = MemoryMarshal.Cast<byte, uint>(encrypted);
            break;
        case CipherMode.CBC:
            AesEngine_X86 aesForRound = new();
            aesForRound.Init(false, keyParameterRound);

            cbcPrecalculated = ReverseArray(encrypted);
            aesForRound.ProcessBlock(cbcPrecalculated, cbcPrecalculated);
            Array.Reverse(cbcPrecalculated);

            baseUIntSpan = MemoryMarshal.Cast<byte, uint>(cbcPrecalculated);
            break;
        default:
            throw new InvalidOperationException("Unhandled mode of operation.");
    }

    uint base0 = baseUIntSpan[0];
    uint base1 = baseUIntSpan[1];
    uint base2 = baseUIntSpan[2];
    uint base3 = baseUIntSpan[3];

    var ivMaterialUIntSpan = MemoryMarshal.Cast<byte, uint>(ivMaterial);
    uint iv0 = ivMaterialUIntSpan[0];
    uint iv1 = ivMaterialUIntSpan[1];
    uint iv2 = ivMaterialUIntSpan[2];
    uint iv3 = ivMaterialUIntSpan[3];

    // Setup parallelism
    List<(uint candidate, byte[] decryption)> candidatesList = new();
    object sync = new();

    using CancellationTokenSource cts = new();
    ParallelOptions options = new()
    {
        CancellationToken = cts.Token,
        MaxDegreeOfParallelism = Environment.ProcessorCount,
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    bool MatchCodeAddress(uint address)
    {
        // Lowest bit set for Thumb instructions
        if ((address & 1) == 0) return false;
        // Address within valid memory region
        if (!(
            (address >= 0x0 && address < 0x10000) || // PRAM
            (address >= 0x10000000 && address < 0x10100000) || // I-cache
            (address >= 0x18000000 && address < 0x18040000) || // SRAM
            (address >= SPI_FLASH_ADDR && address < SPI_FLASH_ADDR + 0x10000000) || // Flash
            (address >= 0x30000000 && address < 0x40000000) // PSRAM
            ))
            return false;

        return true;
    }

    try
    {
        Parallel.For(0, (long)uint.MaxValue + 1, options,
            () =>
            {
                var state = new ThreadState
                {
                    roundIv = new byte[ivMaterial.Length],
                    aesForIv = new(),
                    aesForRound = new()
                };

                state.aesForIv.Init(true, keyParameterIv);
                if (aesMode == CipherMode.OFB)
                {
                    state.aesForRound.Init(true, keyParameterRound);
                }

                return state;
            },
            (deviceKey, _, threadState) =>
            {
                if (deviceKey % 0x1000000 == 0) Console.Error.WriteLine($"0x{deviceKey:x8}");

                /*
                 * Iteration overview:
                 * 1. Create the IV to use for next round
                 *    - XOR device key on to first 16 bytes of firmware key
                 *    - Encrypt using the second 16 bytes of firmware key
                 * 2. Process mode-specific operation
                 *    a. In OFB mode, the IV needs to be encrypted
                 *    b. In CBC mode, the block needs to be decrypted, but since that is independent of the IV,
                 *       it's precomputed
                 * 3. Apply IV to block
                 *    a. In OFB mode, the processed IV is XORed with the encrypted data
                 *    b. in CBC mode, the IV is XORed with the decrypted data
                 *
                 * We're only interested in the first block, so don't need to think about what happens afterwards
                 * (for CBC, we don't need the initial IV past the first block of each chunk. While decrypting
                 * two blocks for OFB will allow us to be certain of the device key due to the reserved vectors
                 * usually being filled with zeroes, it requires different optimization and isn't useful for
                 * CBC mode).
                 */

                // Generate IV
                byte[] roundIv = threadState.roundIv;
                uint reversedDeviceKey = BinaryPrimitives.ReverseEndianness((uint)deviceKey);
                var roundIvUIntSpan = MemoryMarshal.Cast<byte, uint>(roundIv);
                roundIvUIntSpan[0] = iv0 ^ reversedDeviceKey;
                roundIvUIntSpan[1] = iv1 ^ reversedDeviceKey;
                roundIvUIntSpan[2] = iv2 ^ reversedDeviceKey;
                roundIvUIntSpan[3] = iv3 ^ reversedDeviceKey;

                threadState.aesForIv.ProcessBlock(roundIv, roundIv);

                // Process block
                if (aesMode == CipherMode.OFB)
                {
                    threadState.aesForRound.ProcessBlock(roundIv, roundIv);
                }

                uint sp = base0 ^ BinaryPrimitives.ReverseEndianness(roundIvUIntSpan[3]);
                // Front-load stack pointer check: within SRAM range + 8-byte alignment
                if ((sp & 7) == 0 && sp >= 0x18000000 && sp < 0x18040000)
                {
                    uint reset = base1 ^ BinaryPrimitives.ReverseEndianness(roundIvUIntSpan[2]);
                    uint nmi = base2 ^ BinaryPrimitives.ReverseEndianness(roundIvUIntSpan[1]);
                    uint hardFault = base3 ^ BinaryPrimitives.ReverseEndianness(roundIvUIntSpan[0]);

                    // Check handlers
                    bool match = MatchCodeAddress(reset);
                    if (match) match &= MatchCodeAddress(nmi);
                    if (match) match &= MatchCodeAddress(hardFault);

                    if (match)
                    {
                        byte[] captureDecrypted = new byte[16];
                        var captureUIntSpan = MemoryMarshal.Cast<byte, uint>(captureDecrypted);
                        captureUIntSpan[0] = sp;
                        captureUIntSpan[1] = reset;
                        captureUIntSpan[2] = nmi;
                        captureUIntSpan[3] = hardFault;

                        lock (sync)
                        {
                            candidatesList.Add(new((uint)deviceKey, captureDecrypted));
                        }
                    }
                }

                return threadState;
            },
            _ => { });
    }
    catch (OperationCanceledException)
    {
    }

    Console.Error.WriteLine();

    int CountZeroes(byte[] arr)
    {
        int numZeroes = 0;
        foreach (var b in arr)
        {
            if ((b & 0x0f) == 0) ++numZeroes;
            if ((b & 0xf0) == 0) ++numZeroes;
        }
        return numZeroes;
    }

    if (candidatesList.Count > 0)
    {
        foreach (var tup in candidatesList.OrderByDescending(t => CountZeroes(t.decryption)).ThenBy(t => t.candidate))
        {
            Console.WriteLine($"0x{tup.candidate:x8}: {BitConverter.ToUInt32(tup.decryption, 0):x8} {BitConverter.ToUInt32(tup.decryption, 4):x8} {BitConverter.ToUInt32(tup.decryption, 8):x8} {BitConverter.ToUInt32(tup.decryption, 12):x8}");
        }
    }
    else
    {
        Console.WriteLine("No candidates found.");
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Something went wrong: {ex}");
    return 2;
}

return 0;

class ThreadState
{
    public required byte[] roundIv;
    public AesEngine_X86 aesForRound;
    public AesEngine_X86 aesForIv;
}
