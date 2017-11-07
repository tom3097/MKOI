using System;
using System.Linq;
using JetBrains.Annotations;

namespace MKOI
{
    public class ChaChaCipherEngine
    {
        #region fields
        // Magic values defined by the standard
        private static readonly uint[] Constants = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
        private static readonly uint BlockSize = 64;
        private static readonly uint NumberOfRounds = 20;

        #endregion

        #region methods

        /// <summary>
        /// Encrypts or decrypts given bytes using 256 bit key and 64 bit nonce.
        /// </summary>
        /// <param name="input">Array of bytes to encrypt/decrypt</param>
        /// <param name="key">Array of 32 bytes containing the key</param>
        /// <param name="nonce">Array of 8 bytes containing the nonce (initialisation vector)</param>
        /// <returns>Array of decrypted/encrypted bytes of the same length as the input array</returns>
        [NotNull]
        public static byte[] EncryptionDecryption([NotNull] byte[] input, [NotNull] byte[] key, [NotNull] byte[] nonce)
        {
            if (key.Length != 32)
            {
                throw new ArgumentException("Key should have 256 bits.");
            }
            if (nonce.Length != 8)
            {
                throw new ArgumentException("Nonce should have 64 bits.");
            }

            uint totalBlockNumber = (uint) (input.Length % BlockSize == 0 ? input.Length / BlockSize : input.Length / BlockSize + 1);
            byte[] output = new byte[input.Length];
            for (uint blockNumber = 0; blockNumber < totalBlockNumber; ++blockNumber)
            {
                // 16 4-bytes integers
                uint[] initialBlock = GetInitialBlock(key, nonce, blockNumber);
                uint[] transformedBlock = GetTransformedBlock(initialBlock);

                // Add every word from the initial block to the transformed block
                for (int i = 0; i < initialBlock.Length; ++i)
                {
                    transformedBlock[i] += initialBlock[i];
                }

                // Serialize the array of integers into little endian array of bytes
                byte[] keyStream = GetKeyStream(transformedBlock);
                XorArrays(input, output, keyStream, blockNumber * BlockSize);
            }

            return output;
        }

        private static uint[] GetInitialBlock(byte[] key, byte[] nonce, ulong counter)
        {
            uint[] block = new uint[BlockSize / sizeof(uint)];
            // Words 0-3 are initialised by constants.
            for (int i = 0; i < 4; ++i)
            {
                block[i] = Constants[i];
            }

            // Words 4-11 are initialized by the key
            for (uint i = 4; i < 12; ++i)
            {
                block[i] = GetLittleEndianIntegerFromByteArray(key, (i - 4) * 4);
            }

            // Words 12-13 are initialised by the block counter
            block[12] = (uint) (counter & 0xFFFFFFFF);
            block[13] = (uint) (counter >> 32);

            // Words 14-15 are initialized by the nonce
            block[14] = GetLittleEndianIntegerFromByteArray(nonce, 0);
            block[15] = GetLittleEndianIntegerFromByteArray(nonce, 4);
            return block;
        }

        private static uint[] GetTransformedBlock(uint[] inputBlock)
        {
            uint[] returnBlock = inputBlock.ToArray();
            // Each loop runs two algorithm rounds - one column and one diagonal round.
            for (int round = 0; round < NumberOfRounds; round += 2)
            {
                // Column round consisting of 4 quarter rounds
                for (byte i = 0; i < 4; ++i)
                {
                    byte[] indexes = { i, (byte)(i + 4), (byte)(i + 8), (byte)(i + 12) };
                    QuarterRound(returnBlock, indexes);
                }

                // Diagonal round consisting of 4 quarter rounds
                QuarterRound(returnBlock, new byte[] { 0, 5, 10, 15 });
                QuarterRound(returnBlock, new byte[] { 1, 6, 11, 12 });
                QuarterRound(returnBlock, new byte[] { 2, 7, 8, 13 });
                QuarterRound(returnBlock, new byte[] { 3, 4, 9, 14 });
            }
            return returnBlock;
        }

        private static byte[] GetKeyStream(uint[] transformedBlock)
        {
            byte[] keyStream = new byte[BlockSize];
            for (int i = 0; i < transformedBlock.Length; ++i)
            {
                keyStream[4 * i] = (byte)(transformedBlock[i] & 0xff);
                keyStream[4 * i + 1] = (byte)((transformedBlock[i] >> 8) & 0xff);
                keyStream[4 * i + 2] = (byte)((transformedBlock[i] >> 16) & 0xff);
                keyStream[4 * i + 3] = (byte)((transformedBlock[i] >> 24) & 0xff);
            }
            return keyStream;
        }

        private static void XorArrays(byte[] input, byte[] output, byte[] keyStream, uint offset)
        {
            for (int i = 0; i < keyStream.Length && i + offset < input.Length; ++i)
            {
                output[i + offset] = (byte)(input[i + offset] ^ keyStream[i]);
            }
        }

        /// <summary>
        /// Basic operation of the ChaCha algorithm. It manipulates 4 choosen integers from given block.
        /// </summary>
        /// <param name="indexes">Array of 4 indexes of the integers to be changed</param>
        private static void QuarterRound(uint[] block, byte[] indexes)
        {
            uint a = block[indexes[0]];
            uint b = block[indexes[1]];
            uint c = block[indexes[2]];
            uint d = block[indexes[3]];
            
            a += b; d ^= a; d = RotateLeft(d, 16);
            c += d; b ^= c; b = RotateLeft(b, 12);
            a += b; d ^= a; d = RotateLeft(d, 8);
            c += d; b ^= c; b = RotateLeft(b, 7);

            block[indexes[0]] = a;
            block[indexes[1]] = b;
            block[indexes[2]] = c;
            block[indexes[3]] = d;
        }

        /// <summary>
        /// Source: https://stackoverflow.com/a/1674182/5459240
        /// </summary>
        private static uint GetLittleEndianIntegerFromByteArray(byte[] data, uint startIndex)
        {
            return (uint) ((data[startIndex])
                   | (data[startIndex + 1] << 8)
                   | (data[startIndex + 2] << 16)
                   | data[startIndex + 3] << 24);
        }

        /// <summary>
        /// Source: https://stackoverflow.com/a/812035/5459240
        /// </summary>
        private static uint RotateLeft(uint value, int count)
        {
            return (value << count) | (value >> (32 - count));
        }

        #endregion
    }
}
