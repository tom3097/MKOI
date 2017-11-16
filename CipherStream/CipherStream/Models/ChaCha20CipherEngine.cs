using System;
using JetBrains.Annotations;
using System.Linq;
using System.Text;

namespace CipherStream.Models
{
    /// <summary>
    /// ChaCha20CipherEngine class.
    /// This class implements a method which allows to perform encryption and decryption
    /// tasks using ChaCha20 cipher.
    /// </summary>
    public class ChaCha20CipherEngine
    {
        #region fields

        /// <summary>
        /// 'Constants' magic value defined by the standard.
        /// </summary>
        private static readonly uint[] Constants = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

        /// <summary>
        /// 'Block size' magic value defined by the standard.
        /// </summary>
        private static readonly uint BlockSize = 64;

        /// <summary>
        /// 'Number of rounds' magic value defined by the standard.
        /// </summary>
        private static readonly uint NumberOfRounds = 20;

        /// <summary>
        /// The key used for encryption and decryption tasks.
        /// </summary>
        private byte[] _key;

        /// <summary>
        /// Simple logger object saving logs to choosen file.
        /// </summary>
        private SimpleLogger _logger;

        #endregion

        #region methods

        /// <summary>
        /// ChaCha20CipherEngine class constructor.
        /// </summary>
        public ChaCha20CipherEngine()
        {
            _key = null;
        }

        /// <summary>
        /// Initializes the engine with the key.
        /// </summary>
        /// <param name="key">Array of 32 bytes containing the key.</param>
        public void Init(byte[] key)
        {
            _key = new byte[key.Length];
            Array.Copy(key, _key, key.Length);

            _logger?.Log("Initialized engine with key: " + BitConverter.ToString(key));
        }

        /// <summary>
        /// Enable writing logs to choosen log file.
        /// </summary>
        /// <param name="logFile"></param>
        public void EnableLogging(string logFile)
        {
            _logger = new SimpleLogger(logFile);
        }

        /// <summary>
        /// Disable logging.
        /// </summary>
        public void DisableLogging()
        {
            _logger = null;
        }

        /// <summary>
        /// Encrypts or decrypts given bytes using 256 bit key and 64 bit nonce.
        /// </summary>
        /// <param name="input">Array of bytes to encrypt/decrypt.</param>
        /// <param name="nonce">Array of 8 bytes containing the nonce (initialisation vector).</param>
        /// <returns>Array of decrypted/encrypted bytes of the same length as the input array.</returns>
        [NotNull]
        public byte[] ProcessBytes([NotNull] byte[] input, [NotNull] byte[] nonce)
        {
            if (_key == null || _key.Length != 32)
            {
                throw new Exception("Key should have 256 bits.");
            }
            if (nonce.Length != 8)
            {
                throw new ArgumentException("Nonce should have 64 bits.");
            }

            _logger?.Log("Using IV: " + BitConverter.ToString(nonce));

            uint totalBlockNumber = (uint)(input.Length % BlockSize == 0 ? input.Length / BlockSize : input.Length / BlockSize + 1);
            byte[] output = new byte[input.Length];
            for (uint blockNumber = 0; blockNumber < totalBlockNumber; ++blockNumber)
            {
                // 16 4-bytes integers
                uint[] initialBlock = GetInitialBlock(_key, nonce, blockNumber);
                uint[] transformedBlock = GetTransformedBlock(initialBlock);

                _logger?.Log("Block before transformation:" + Environment.NewLine + BlockToString(initialBlock));
                _logger?.Log("Block after transformation:" + Environment.NewLine + BlockToString(transformedBlock));

                // Add every word from the initial block to the transformed block
                for (int i = 0; i < initialBlock.Length; ++i)
                {
                    transformedBlock[i] += initialBlock[i];
                }

                // Serialize the array of integers into little endian array of bytes
                byte[] keyStream = GetKeyStream(transformedBlock);

                _logger?.Log("Resulting keystream: " + BitConverter.ToString(keyStream));

                uint offset = blockNumber * BlockSize;
                XorArrays(input, output, keyStream, offset);

                _logger?.Log("Input stream:        " +
                             BitConverter.ToString(input.Skip((int) offset).Take(keyStream.Length).ToArray()));

                _logger?.Log("Output stream:       " + BitConverter.ToString(output.Skip((int) offset).Take(keyStream.Length).ToArray()));
            }

            _logger?.Log("Finished processing input.");
            _logger?.Save();

            return output;
        }

        /// <summary>
        /// Returns 16 four byte words that make up a block of data that is later transformed in method GetTransformedBlock.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="nonce"></param>
        /// <param name="counter"></param>
        /// <returns></returns>
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
            block[12] = (uint)(counter & 0xFFFFFFFF);
            block[13] = (uint)(counter >> 32);

            // Words 14-15 are initialized by the nonce
            block[14] = GetLittleEndianIntegerFromByteArray(nonce, 0);
            block[15] = GetLittleEndianIntegerFromByteArray(nonce, 4);
            return block;
        }

        /// <summary>
        /// Applies 20 rounds of addition xor and shifting on 4 byte integers making up the inputBlock
        /// </summary>
        /// <param name="inputBlock"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Produces an array of bytes from an array of integers, making a keystream.
        /// </summary>
        /// <param name="transformedBlock"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Apply XOR to every corresponding byte of input and keyStream byte arrays and write results to output array. 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="keyStream"></param>
        /// <param name="offset"></param>
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
            return (uint)((data[startIndex])
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

        /// <summary>
        /// Transform array of integers into its string represantation.
        /// </summary>
        /// <param name="block"></param>
        /// <returns></returns>
        private string BlockToString(uint[] block)
        {
            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < block.Length; ++i)
            {
                if (i != 0 && i % 4 == 0)
                {
                    builder.AppendLine();
                }
                builder.Append(block[i].ToString("X8"));
                builder.Append(" ");
            }
            return builder.ToString();
        }

        #endregion
    }
}
