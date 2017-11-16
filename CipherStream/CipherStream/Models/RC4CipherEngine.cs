using System;

namespace CipherStream.Models
{
    /// <summary>
    /// RC4CipherEngine class.
    /// This class implements a method which allows to perform encryption and decryption
    /// tasks using RC4 cipher.
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
        /// Initializes the engine with the key.
        /// </summary>
        /// <param name="key">The key used for encryption and decryption tasks.</param>
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
        /// Performs encryption and decryption tasks.
        /// </summary>
        /// <param name="inBytes">Bytes to be processed.</param>
        /// <returns>Processed output.</returns>
        public byte[] ProcessBytes(byte[] inBytes)
        {
            InitArrayWithKey();

            byte[] keystream = PrepareKeystream(inBytes.Length);
            byte[] outBytes = new byte[inBytes.Length];

            for (int i = 0; i < inBytes.Length; ++i)
            {
                outBytes[i] = (Byte)(inBytes[i] ^ keystream[i]);
                _logger?.Log("Keystream byte: " + Convert.ToString(keystream[i], 2).PadLeft(8, '0'));
                _logger?.Log("Input byte:     " + Convert.ToString(inBytes[i], 2).PadLeft(8, '0'));
                _logger?.Log("Output byte:    " + Convert.ToString(outBytes[i], 2).PadLeft(8 , '0'));
            }

            _logger?.Log("Finished processing input.");
            _logger?.Save();

            return outBytes;
        }

        /// <summary>
        /// Initialized T array based on the given key.
        /// </summary>
        private void InitArrayWithKey()
        {
            if (_key == null)
            {
                throw new NullReferenceException();
            }

            for (int i = 0; i < 256; ++i)
            {
                _T[i] = (byte)i;
            }

            int j = 0;

            for (int i = 0; i < 256; ++i)
            {
                j = (j + _T[i] + _key[i % _key.Length]) % _TSize;
                byte temp = _T[i];
                _T[i] = _T[j];
                _T[j] = temp;
            }

            _logger?.Log("Array T: " + BitConverter.ToString(_T));
        }

        /// <summary>
        /// Prepares keystream needed to perform XOR operation.
        /// </summary>
        /// <param name="length">The length of the keystream.</param>
        /// <returns>The prepared keystream.</returns>
        private byte[] PrepareKeystream(int length)
        {
            byte[] keystream = new byte[length];

            int p1 = 0;
            int p2 = 0;

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

            return keystream;
        }

        #endregion
    }
}
