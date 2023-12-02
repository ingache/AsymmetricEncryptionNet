using System.Security.Cryptography;

namespace AsymmetricEncryptionNet.Services
{
    /// <summary>
    /// A helper class for generating and managing RSA keys.
    /// </summary>
    public class RsaKeyGenerator
    {
        private readonly int keySize = 2048;
        // RSA instance used for cryptographic operations.
        private RSA Rsa { get; }

        /// <summary>
        /// Initializes a new instance of the RsaKeyGenerator class.
        /// </summary>
        public RsaKeyGenerator()
        {
            // Create a new RSA object with a key size of 2048 bits.
            // 2048 bits is generally considered secure for RSA keys.
            Rsa = RSA.Create(keySize);
        }

        /// <summary>
        /// Exports the private key in PEM format.
        /// </summary>
        /// <returns>A string containing the private key in PEM format.</returns>
        public string GetPrivateKeyPEM()
        {
            // Export the private key in PKCS#8 format (Private Key Cryptography Standards).
            // The PKCS#8 format is used for storing private key information.
            return Rsa.ExportPkcs8PrivateKeyPem();
        }

        /// <summary>
        /// Exports the public key in PEM format.
        /// </summary>
        /// <returns>A string containing the public key in PEM format.</returns>
        public string GetPublicKeyPem()
        {
            // Export the RSA public key in PEM format.
            // This format is widely used for exchanging public key information.
            return Rsa.ExportRSAPublicKeyPem();
        }
    }
}



