// See https://aka.ms/new-console-template for more information

#define USE_SSSE3 // Enable SSSE3 optimization

using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using AesIntrinsic = System.Runtime.Intrinsics.X86.Aes;

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

if (!AesIntrinsic.IsSupported || !Sse2.IsSupported)
{
    Console.Error.WriteLine("AES-NI and SSE2 support required.");
    return 4;
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

    #region Adapted from Org.BouncyCastle.Crypto.Engines.AesEngine_X86

    /*
     * Copyright (c) 2000-2025 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org).
     * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
     * associated documentation files (the "Software"), to deal in the Software without restriction,
     * including without limitation the rights to use, copy, modify, merge, publish, distribute,
     * sub license, and/or sell copies of the Software, and to permit persons to whom the Software is
     * furnished to do so, subject to the following conditions: The above copyright notice and this
     * permission notice shall be included in all copies or substantial portions of the Software.
     *
     * **THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
     * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
     * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
     * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
     * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**
     */

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void AesCreateRoundKeys128(ReadOnlySpan<byte> key, Span<Vector128<byte>> K, bool forEncryption)
    {
        ReadOnlySpan<byte> rcon = stackalloc byte[] { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

        var s = MemoryMarshal.Read<Vector128<byte>>(key[..16]);
        K[0] = s;

        for (int round = 0; round < 10;)
        {
            var t = AesIntrinsic.KeygenAssist(s, rcon[round++]);
            t = Sse2.Shuffle(t.AsInt32(), 0xFF).AsByte();
            s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 8));
            t = Sse2.Xor(t, s);
            s = Sse2.Xor(t, Sse2.ShiftLeftLogical128BitLane(s, 4));
            K[round] = s;
        }

        if (!forEncryption)
        {
            for (int i = 1, last = K.Length - 1; i < last; ++i)
            {
                K[i] = AesIntrinsic.InverseMixColumns(K[i]);
            }

            K.Reverse();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void AesCreateRoundKeys256(ReadOnlySpan<byte> key, Span<Vector128<byte>> K, bool forEncryption)
    {
        var s1 = MemoryMarshal.Read<Vector128<byte>>(key[..16]);
        var s2 = MemoryMarshal.Read<Vector128<byte>>(key[16..32]);
        K[0] = s1;
        K[1] = s2;

        byte rcon = 0x01;
        for (int round = 1; ;)
        {
            var t1 = AesIntrinsic.KeygenAssist(s2, rcon); rcon <<= 1;
            t1 = Sse2.Shuffle(t1.AsInt32(), 0xFF).AsByte();
            s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 8));
            t1 = Sse2.Xor(t1, s1);
            s1 = Sse2.Xor(t1, Sse2.ShiftLeftLogical128BitLane(s1, 4));
            K[++round] = s1;

            if (round == 14)
                break;

            var t2 = AesIntrinsic.KeygenAssist(s1, 0x00);
            t2 = Sse2.Shuffle(t2.AsInt32(), 0xAA).AsByte();
            s2 = Sse2.Xor(s2, Sse2.ShiftLeftLogical128BitLane(s2, 8));
            t2 = Sse2.Xor(t2, s2);
            s2 = Sse2.Xor(t2, Sse2.ShiftLeftLogical128BitLane(s2, 4));
            K[++round] = s2;
        }

        if (!forEncryption)
        {
            for (int i = 1, last = K.Length - 1; i < last; ++i)
            {
                K[i] = AesIntrinsic.InverseMixColumns(K[i]);
            }

            K.Reverse();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void AesDecrypt256(ReadOnlySpan<Vector128<byte>> roundKeys, ref Vector128<byte> state)
    {
        var bounds = roundKeys[14];
        var value = Sse2.Xor(state, roundKeys[0]);
        value = AesIntrinsic.Decrypt(value, roundKeys[1]);
        value = AesIntrinsic.Decrypt(value, roundKeys[2]);
        value = AesIntrinsic.Decrypt(value, roundKeys[3]);
        value = AesIntrinsic.Decrypt(value, roundKeys[4]);
        value = AesIntrinsic.Decrypt(value, roundKeys[5]);
        value = AesIntrinsic.Decrypt(value, roundKeys[6]);
        value = AesIntrinsic.Decrypt(value, roundKeys[7]);
        value = AesIntrinsic.Decrypt(value, roundKeys[8]);
        value = AesIntrinsic.Decrypt(value, roundKeys[9]);
        value = AesIntrinsic.Decrypt(value, roundKeys[10]);
        value = AesIntrinsic.Decrypt(value, roundKeys[11]);
        value = AesIntrinsic.Decrypt(value, roundKeys[12]);
        value = AesIntrinsic.Decrypt(value, roundKeys[13]);
        state = AesIntrinsic.DecryptLast(value, roundKeys[14]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void AesEncrypt128(ReadOnlySpan<Vector128<byte>> roundKeys, ref Vector128<byte> state)
    {
        var bounds = roundKeys[10];
        var value = Sse2.Xor(state, roundKeys[0]);
        value = AesIntrinsic.Encrypt(value, roundKeys[1]);
        value = AesIntrinsic.Encrypt(value, roundKeys[2]);
        value = AesIntrinsic.Encrypt(value, roundKeys[3]);
        value = AesIntrinsic.Encrypt(value, roundKeys[4]);
        value = AesIntrinsic.Encrypt(value, roundKeys[5]);
        value = AesIntrinsic.Encrypt(value, roundKeys[6]);
        value = AesIntrinsic.Encrypt(value, roundKeys[7]);
        value = AesIntrinsic.Encrypt(value, roundKeys[8]);
        value = AesIntrinsic.Encrypt(value, roundKeys[9]);
        state = AesIntrinsic.EncryptLast(value, roundKeys[10]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void AesEncrypt256(ReadOnlySpan<Vector128<byte>> roundKeys, ref Vector128<byte> state)
    {
        var bounds = roundKeys[14];
        var value = Sse2.Xor(state, roundKeys[0]);
        value = AesIntrinsic.Encrypt(value, roundKeys[1]);
        value = AesIntrinsic.Encrypt(value, roundKeys[2]);
        value = AesIntrinsic.Encrypt(value, roundKeys[3]);
        value = AesIntrinsic.Encrypt(value, roundKeys[4]);
        value = AesIntrinsic.Encrypt(value, roundKeys[5]);
        value = AesIntrinsic.Encrypt(value, roundKeys[6]);
        value = AesIntrinsic.Encrypt(value, roundKeys[7]);
        value = AesIntrinsic.Encrypt(value, roundKeys[8]);
        value = AesIntrinsic.Encrypt(value, roundKeys[9]);
        value = AesIntrinsic.Encrypt(value, roundKeys[10]);
        value = AesIntrinsic.Encrypt(value, roundKeys[11]);
        value = AesIntrinsic.Encrypt(value, roundKeys[12]);
        value = AesIntrinsic.Encrypt(value, roundKeys[13]);
        state = AesIntrinsic.EncryptLast(value, roundKeys[14]);
    }

    #endregion

    // Setup AES
    var KRound = new Vector128<byte>[15];
    var KIv = new Vector128<byte>[11];
    AesCreateRoundKeys256(inKey, KRound, true);
    AesCreateRoundKeys128(inKey.AsSpan().Slice(0, 16), KIv, true);

    // Precalculate some stuff for hot path
    byte[] cbcPrecalculated;
    Span<uint> baseUIntSpan;
    switch (aesMode)
    {
        case CipherMode.OFB:
            baseUIntSpan = MemoryMarshal.Cast<byte, uint>(encrypted);
            break;
        case CipherMode.CBC:
            Span<Vector128<byte>> K = stackalloc Vector128<byte>[15];
            AesCreateRoundKeys256(inKey, K, false);

            cbcPrecalculated = ReverseArray(encrypted);
            var block = MemoryMarshal.Read<Vector128<byte>>(cbcPrecalculated);
            AesDecrypt256(K, ref block);
            MemoryMarshal.Write(cbcPrecalculated, block);
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

#if USE_SSSE3
    var baseVector = MemoryMarshal.Read<Vector128<uint>>(MemoryMarshal.Cast<uint, byte>(baseUIntSpan));
    var shuffleMask = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
#endif

    var ivMaterialVector = MemoryMarshal.Read<Vector128<uint>>(inKey.AsSpan(0x10, 0x10));

    // Setup parallelism
    List<(uint candidate, byte[] decryption)> candidatesList = new();
    object sync = new();

    using CancellationTokenSource cts = new();
    ParallelOptions options = new()
    {
        CancellationToken = cts.Token,
        MaxDegreeOfParallelism = Environment.ProcessorCount,
    };

    long totalCount = (long)uint.MaxValue + 1;
    const long partitionSize = 0x100000;
    var partitioner = Partitioner.Create(0, totalCount, partitionSize);
    //Console.Error.WriteLine($"Partition size: 0x{partitionSize:x}");

    IProgress<long> progress = new Progress<long>(count =>
    {
        Console.Error.WriteLine($"0x{count:x8} ({(float)count / totalCount:P})");
    });

    long completed = 0;
    using System.Timers.Timer progressTimer = new(500);
    progressTimer.Elapsed += (_, _) =>
    {
        progress.Report(Volatile.Read(ref completed));
    };

    Stopwatch procStopwatch = new();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool MatchCodeAddress(uint address)
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

    void CancelHandler(object? sender, ConsoleCancelEventArgs e)
    {
        cts.Cancel();
        e.Cancel = true;
    }

    Console.CancelKeyPress += CancelHandler;

    try
    {
        progressTimer.Start();
        procStopwatch.Start();
        Parallel.ForEach(partitioner, options,
            () =>
            {
                return new ThreadState();
            },
            (range, _, threadState) =>
            {
                for (long deviceKey = range.Item1; deviceKey < range.Item2; ++deviceKey)
                {
                    /*
                     * Iteration overview:
                     * -> Assume key already reversed to match how the on-device AES peripheral processes things
                     * 1. Create the IV to use for this iteration
                     *    - XOR device key on to second 16 bytes of firmware key
                     *    - Encrypt using the first 16 bytes of firmware key
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
                    uint reversedDeviceKey = BinaryPrimitives.ReverseEndianness((uint)deviceKey);
                    var multiDeviceKeys = Vector128.Create(reversedDeviceKey, reversedDeviceKey, reversedDeviceKey, reversedDeviceKey);
                    var uintBlock = Sse2.Xor(ivMaterialVector, multiDeviceKeys);
                    var block = uintBlock.AsByte();

                    AesEncrypt128(KIv, ref block);

                    // Process block
                    if (aesMode == CipherMode.OFB)
                    {
                        AesEncrypt256(KRound, ref block);
                    }

                    uintBlock = block.AsUInt32();

#if USE_SSSE3
                    if (Ssse3.IsSupported)
                    {
                        var revBlock = Ssse3.Shuffle(block, shuffleMask).AsUInt32();
                        var baseProcBlock = Sse2.Xor(baseVector, revBlock);

                        // Front-load stack pointer check: within SRAM range + 8-byte alignment
                        var sp = baseProcBlock[0];
                        if ((sp & 7) == 0 && sp >= 0x18000000 && sp < 0x18040000)
                        {
                            // Check handlers
                            if (MatchCodeAddress(baseProcBlock[1]) && MatchCodeAddress(baseProcBlock[2]) && MatchCodeAddress(baseProcBlock[3]))
                            {
                                byte[] captureDecrypted = GC.AllocateUninitializedArray<byte>(16);
                                var captureUIntSpan = MemoryMarshal.Cast<byte, uint>(captureDecrypted);
                                baseProcBlock.CopyTo(captureUIntSpan);

                                threadState.localList.Add(new((uint)deviceKey, captureDecrypted));
                            }
                        }
                    }
                    else
                    {
#endif
                        uint sp = base0 ^ BinaryPrimitives.ReverseEndianness(uintBlock[3]);
                        // Front-load stack pointer check: within SRAM range + 8-byte alignment
                        if ((sp & 7) == 0 && sp >= 0x18000000 && sp < 0x18040000)
                        {
                            uint reset = base1 ^ BinaryPrimitives.ReverseEndianness(uintBlock[2]);
                            uint nmi = base2 ^ BinaryPrimitives.ReverseEndianness(uintBlock[1]);
                            uint hardFault = base3 ^ BinaryPrimitives.ReverseEndianness(uintBlock[0]);

                            // Check handlers
                            if (MatchCodeAddress(reset) && MatchCodeAddress(nmi) && MatchCodeAddress(hardFault))
                            {
                                byte[] captureDecrypted = GC.AllocateUninitializedArray<byte>(16);
                                var captureUIntSpan = MemoryMarshal.Cast<byte, uint>(captureDecrypted);
                                captureUIntSpan[0] = sp;
                                captureUIntSpan[1] = reset;
                                captureUIntSpan[2] = nmi;
                                captureUIntSpan[3] = hardFault;

                                threadState.localList.Add(new((uint)deviceKey, captureDecrypted));
                            }
                        }
#if USE_SSSE3
                    }
#endif
                }

                Interlocked.Add(ref completed, range.Item2 - range.Item1);
                return threadState;
            },
            threadState =>
            {
                if (threadState.localList.Count != 0)
                {
                    lock (sync)
                    {
                        candidatesList.AddRange(threadState.localList);
                    }
                }
            });
    }
    catch (OperationCanceledException)
    {
    }
    procStopwatch.Stop();
    progressTimer.Stop();
    Console.CancelKeyPress -= CancelHandler;

    Console.Error.WriteLine($"Elapsed: {procStopwatch.Elapsed}");
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
    public List<(uint, byte[])> localList = new(16);
}
