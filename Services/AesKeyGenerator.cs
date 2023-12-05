using System;
using System.Security.Cryptography;

namespace AsymmetricEncryptionNet.Services 
{
    public class Aes256KeyGenerator
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public Aes256KeyGenerator()
        {
            using (var aes = Aes.Create())
            {
                if (aes == null)
                    throw new InvalidOperationException("Failed to create AES instance.");

                aes.KeySize = 256; // Setting the KeySize to 256 bits
                aes.GenerateKey(); // Generating the key
                aes.GenerateIV();  // Generating the IV

                _key = aes.Key;
                _iv = aes.IV;
            }
        }

        public string Key => Convert.ToBase64String(_key);
        public string IV => Convert.ToBase64String(_iv);
    }
}

