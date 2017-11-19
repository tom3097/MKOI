using System;

namespace CipherStream.Models
{
    /// <summary>
    /// RC4CipherEngine class.
    /// This class implements RC4 cipher. RC4 is a symmetric stream cipher, known and praised for its speed and simplicity.
    /// RC4CipherEngine provides methods responsible for: initialization, encryption / decryption tasks and managing logger state.
    /// </summary>
    public class RC4CipherEngine
    {
        #region fields

        /// <summary>
        /// The size of the T array.
        /// </summary>
        private const int _TSize = 256;

        /// <summary>
        /// T array used for encryption and decryption tasks.
        /// </summary>
        private byte[] _T;

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
        /// RC4CipherEngine class constructor.
        /// </summary>
        public RC4CipherEngine()
        {
            _T = new byte[_TSize];

            _key = null;
        }

        /// <summary>
        /// Initializes the cipher's engine with the given key.
        /// </summary>
        /// <param name="key">The key which is to be used as an engine initializer.</param>
        public void Init(byte[] key)
        {
            _key = new byte[key.Length];
            Array.Copy(key, _key, key.Length);

            _logger?.Log("Initialized engine with key: " + BitConverter.ToString(key));
        }

        /// <summary>
        /// Enables logging to associated log file.
        /// </summary>
        /// <param name="logFile">Associated log file.</param>
        public void EnableLogging(string logFile)
        {
            _logger = new SimpleLogger(logFile);
        }

        /// <summary>
        /// Disables logging.
        /// </summary>
        public void DisableLogging()
        {
            _logger = null;
        }

        /// <summary>
        /// Performs encryption / decryption task on the given input bytes.
        /// </summary>
        /// <param name="inBytes">Input bytes which are to be processed.</param>
        /// <returns>Processed output bytes (received after encryption / decryption).</returns>
        public byte[] ProcessBytes(byte[] inBytes)
        {
            InitArrayWithKey();

            byte[] keystream = PrepareKeystream(inBytes.Length);
            byte[] outBytes = new byte[inBytes.Length];

            _logger?.Log("Processing input bytes...");
            _logger?.Log("Performing encryption / decryption using binary XOR operator: output byte[i] = " +
                "'keystream[i]' ^ input byte[i], for each 'i' index in input bytes (0 <= 'i' <= input data size).");
            for (int i = 0; i < inBytes.Length; ++i)
            {
                outBytes[i] = (Byte)(inBytes[i] ^ keystream[i]);
                _logger?.Log("XORing keystream with input: " + Convert.ToString(keystream[i], 2).PadLeft(8, '0') + " XOR " + Convert.ToString(inBytes[i], 2).PadLeft(8, '0')
                                    + " = " + Convert.ToString(outBytes[i], 2).PadLeft(8, '0'));
            }

            _logger?.Log("Created output byte array: " + BitConverter.ToString(outBytes));
            _logger?.Log("Input bytes processed.");
            _logger?.Save();

            return outBytes;
        }

        /// <summary>
        /// Initialized T array based on the given key.
        /// </summary>
        private void InitArrayWithKey()
        {
            _logger?.Log("Initializing 'T' array...");
            if (_key == null)
            {
                throw new NullReferenceException();
            }

            _logger?.Log("Performing assignment operation 'T[i]' = 'i' for each element in 'T' array (0 <= 'i' <= 255).");
            for (int i = 0; i < 256; ++i)
            {
                _T[i] = (byte)i;
            }

            _logger.Log("Initializing temporary variable 'j' with '0' value.");
            int j = 0;

            _logger.Log("Performing two operations for each 'i' index in 'T' array (0 <= 'i' <= 255).");
            _logger.Log("Operation 1 - calculating new 'j' value using formula: 'j' = ('j' + 'T[i]' + key['i' % key length]) % 'T' size.");
            _logger.Log("Operation 2 - swapping 'T[i]' and 'T[j]'.");
            for (int i = 0; i < 256; ++i)
            {
                j = (j + _T[i] + _key[i % _key.Length]) % _TSize;
                byte temp = _T[i];
                _T[i] = _T[j];
                _T[j] = temp;
            }

            _logger?.Log("Created 'T' array: " + BitConverter.ToString(_T));
            _logger?.Log("'T' array initialized.");
        }

        /// <summary>
        /// Prepares keystream needed to perform XOR operation.
        /// </summary>
        /// <param name="length">The length of the keystream.</param>
        /// <returns>The prepared keystream.</returns>
        private byte[] PrepareKeystream(int length)
        {
            _logger?.Log("Generating cipher keystream...");
            byte[] keystream = new byte[length];

            _logger?.Log("Initializing temporary variables 'p1' and 'p2' with '0' values.");
            int p1 = 0;
            int p2 = 0;

            _logger?.Log("Performing four operations for each 'i' index in input data array (0 <= 'i' <= input data size).");
            _logger?.Log("Operation 1 - calculating new 'p1' value using formula: 'p1' = ('p1' + 1) % 'T' size.");
            _logger?.Log("Operation 2 - calculating new 'p2' value using formula: 'p2' = ('p2' + 'T[p1]') % 'T' size.");
            _logger?.Log("Operation 3 - swapping 'T[p1]' and 'T[p2]'.");
            _logger?.Log("Operation 4 - calculating 'keystream[i]' using formula: ('T[p1]' + 'T[p2]') % 'T' size.");
            for (int i = 0; i < length; ++i)
            {
                p1 = (p1 + 1) % _TSize;
                p2 = (p2 + _T[p1]) % _TSize;

                byte temp = _T[p1];
                _T[p1] = _T[p2];
                _T[p2] = temp;

                int p3 = (_T[p1] + _T[p2]) % _TSize;

                keystream[i] = _T[p3];
            }

            _logger?.Log("Created keystream: " + BitConverter.ToString(keystream));
            _logger?.Log("Cipher keystream generated.");

            return keystream;
        }

        #endregion
    }
}
