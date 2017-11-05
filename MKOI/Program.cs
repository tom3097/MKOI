using System;

namespace MKOI
{
    class Program
    {
        static void Main(string[] args)
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
        }
    }
}
