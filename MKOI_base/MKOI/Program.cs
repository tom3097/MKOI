using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Text;

namespace MKOI
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("RC4:");
            ShowRC4();
            Console.WriteLine();
            Console.WriteLine("ChaCha20:");
            ShowChaCha20();
        }

        static void ShowRC4()
        {
            /* See https://en.wikipedia.org/wiki/RC4, Description -> Test vectors section */

            /* test case 1 */
            var key = "Key";
            Console.WriteLine("Key: {0}", key);

            var text = "Plaintext";
            Console.WriteLine("Text before encryption: {0}", text);

            var encrypted = RC4CipherEngine.EncryptionDecryption(key, text);
            Console.Write("Text after encryption: ");
            foreach (var e in encrypted)
            {
                Console.Write(e.ToString("X2"));
            }
            Console.WriteLine();

            var decrypted = RC4CipherEngine.EncryptionDecryption(key, encrypted);
            Console.Write("Text after decryption: ");
            foreach (var d in decrypted)
            {
                Console.Write((char)d);
            }
            Console.WriteLine();

            /* test case 2 */
            key = "Wiki";
            Console.WriteLine("Key: {0}", key);

            text = "pedia";
            Console.WriteLine("Text before encryption: {0}", text);

            encrypted = RC4CipherEngine.EncryptionDecryption(key, text);
            Console.Write("Text after encryption: ");
            foreach (var e in encrypted)
            {
                Console.Write(e.ToString("X2"));
            }
            Console.WriteLine();

            decrypted = RC4CipherEngine.EncryptionDecryption(key, encrypted);
            Console.Write("Text after decryption: ");
            foreach (var d in decrypted)
            {
                Console.Write((char)d);
            }
            Console.WriteLine();

            /* test case 3 */
            key = "Secret";
            Console.WriteLine("Key: {0}", key);

            text = "Attack at dawn";
            Console.WriteLine("Text before encryption: {0}", text);

            encrypted = RC4CipherEngine.EncryptionDecryption(key, text);
            Console.Write("Text after encryption: ");
            foreach (var e in encrypted)
            {
                Console.Write(e.ToString("X2"));
            }
            Console.WriteLine();

            decrypted = RC4CipherEngine.EncryptionDecryption(key, encrypted);
            Console.Write("Text after decryption: ");
            foreach (var d in decrypted)
            {
                Console.Write((char)d);
            }
            Console.WriteLine();


            /* wykorzystanie biblioteki */

            var rc4Bouncy = new RC4Engine();

            var keyy = Encoding.UTF8.GetBytes("Key");

            rc4Bouncy.Init(true, new KeyParameter(keyy));

            byte[] inBytes = Encoding.UTF8.GetBytes("Plaintext");
            byte[] outBuffer = new byte[inBytes.Length];
            rc4Bouncy.ProcessBytes(inBytes, 0, inBytes.Length, outBuffer, 0);

            for(int i = 0; i < outBuffer.Length; ++i)
            {
                Console.Write(outBuffer[i].ToString("X2"));
            }
            Console.WriteLine();

            rc4Bouncy.Init(false, new KeyParameter(keyy));
            byte[] outoutBuffer = new byte[outBuffer.Length];
            rc4Bouncy.ProcessBytes(outBuffer, 0, outBuffer.Length, outoutBuffer, 0);

            for (int i = 0; i < outBuffer.Length; ++i)
            {
                Console.Write((char)outoutBuffer[i]);
            }
            Console.WriteLine();
        }

        static void ShowChaCha20()
        {
            /* test case 1 */
            var key = CreateString(32);
            Console.WriteLine("256 bit key: {0}", key);
            var nonce = CreateString(8);
            Console.WriteLine("64 bit nonce (initialisation vector): {0}", nonce);

            var text = "Plaintext";
            Console.WriteLine("Text before encryption: {0}", text);

            var keyInBytes = Encoding.UTF8.GetBytes(key);
            var nonceInBytes = Encoding.UTF8.GetBytes(nonce);
            var textInBytes = Encoding.UTF8.GetBytes(text);

            var encrypted = ChaChaCipherEngine.EncryptionDecryption(textInBytes, keyInBytes, nonceInBytes);

            Console.Write("Text after encryption: ");
            foreach (var e in encrypted)
            {
                Console.Write(e.ToString("X2"));
            }
            Console.WriteLine();

            var decrypted = ChaChaCipherEngine.EncryptionDecryption(
                encrypted,
                keyInBytes,
                nonceInBytes);
            Console.Write("Text after decryption: ");
            foreach (var d in decrypted)
            {
                Console.Write((char)d);
            }
            Console.WriteLine();
            
            // Mixing custom implementation and BouncyCastle

            var chachaBouncy = new ChaChaEngine();

            // Initialize for encryption
            chachaBouncy.Init(true, new ParametersWithIV(
                new KeyParameter(keyInBytes),
                nonceInBytes));

            byte[] outBuffer = new byte[textInBytes.Length];
            chachaBouncy.ProcessBytes(textInBytes, 0, textInBytes.Length, outBuffer, 0);

            Console.WriteLine("Text encrypted with BouncyCastle:");
            for (int i = 0; i < outBuffer.Length; ++i)
            {
                Console.Write(outBuffer[i].ToString("X2"));
            }
            Console.WriteLine();

            decrypted = ChaChaCipherEngine.EncryptionDecryption(outBuffer, keyInBytes, nonceInBytes);
            Console.Write("Text decrypted with custom implementation:");
            foreach (var d in decrypted)
            {
                Console.Write((char)d);
            }
            Console.WriteLine();
        }

        /// <summary>
        /// Source: https://stackoverflow.com/a/4616745/5459240
        /// </summary>
        private static string CreateString(int stringLength)
        {
            Random rd = new Random();
            const string allowedChars = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789!@$?_-";
            char[] chars = new char[stringLength];

            for (int i = 0; i < stringLength; i++)
            {
                chars[i] = allowedChars[rd.Next(0, allowedChars.Length)];
            }

            return new string(chars);
        }
    }
}
