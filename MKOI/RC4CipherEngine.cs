using System;
using System.Collections.Generic;

namespace MKOI
{
    /// <summary>
    /// RC4CipherEngine class.
    /// This class implements a method which allows to perform encryption and decryption
    /// tasks using RC4 cipher.
    /// </summary>
    public static class RC4CipherEngine
    {
        #region fields

        /// <summary>
        /// The size of the T array.
        /// </summary>
        private const int _TSize = 256;

        /// <summary>
        /// T array used for encryption and decryption tasks.
        /// </summary>
        private static Byte[] _T;

        #endregion

        #region methods

        /// <summary>
        /// RC4CipherEngine class constructor.
        /// </summary>
        /// <param name="key">RC4 cipher key.</param>
        static RC4CipherEngine()
        {
            _T = new Byte[_TSize];
        }

        /// <summary>
        /// Initialized T array based on the key given as a parameter.
        /// </summary>
        /// <param name="key">RC4 cipher key.</param>
        private static void InitArrayWithKey(string key)
        {
            for (int i = 0; i < 256; ++i)
            {
                _T[i] = (Byte)i;
            }

            int j = 0;

            for (int i = 0; i < 256; ++i)
            {
                j = (j + _T[i] + key[i % key.Length]) % _TSize;
                Byte temp = _T[i];
                _T[i] = _T[j];
                _T[j] = temp;
            }
        }

        /// <summary>
        /// Prepares keystream needed to perform XOR operation.
        /// </summary>
        /// <param name="length">The length of the keystream.</param>
        /// <returns></returns>
        private static List<Byte> PrepareKeystream(int length)
        {
            List<Byte> keystream = new List<Byte>();

            int p1 = 0;
            int p2 = 0;

            for (int i = 0; i < length; ++i)
            {
                p1 = (p1 + 1) % _TSize;
                p2 = (p2 + _T[p1]) % _TSize;

                Byte temp = _T[p1];
                _T[p1] = _T[p2];
                _T[p2] = temp;

                int p3 = (_T[p1] + _T[p2]) % _TSize;

                keystream.Add(_T[p3]);
            }

            return keystream;
        }

        /// <summary>
        /// Performs encryption and decryption tasks.
        /// </summary>
        /// <param name="key">RC4 cipher key.</param>
        /// <param name="text">Text which is to be encrypted / decrypted.</param>
        /// <returns></returns>
        public static List<Byte> EncryptionDecryption(string key, string text)
        {
            InitArrayWithKey(key);

            List<Byte> keystream = PrepareKeystream(text.Length);

            List<Byte> cipherText = new List<Byte>();

            for (int i = 0; i < text.Length; ++i)
            {
                cipherText.Add((Byte)(text[i] ^ keystream[i]));
            }

            return cipherText;
        }

        /// <summary>
        /// Performs encryption and decryption tasks.
        /// </summary>
        /// <param name="key">RC4 cipher key.</param>
        /// <param name="text">Text which is to be encrypted / decrypted.</param>
        /// <returns></returns>
        public static List<Byte> EncryptionDecryption(string key, List<Byte> text)
        {
            InitArrayWithKey(key);

            List<Byte> keystream = PrepareKeystream(text.Count);

            List<Byte> cipherText = new List<Byte>();

            for (int i = 0; i < text.Count; ++i)
            {
                cipherText.Add((Byte)(text[i] ^ keystream[i]));
            }

            return cipherText;
        }

        #endregion
    }
}
