using System.Security.Cryptography;

namespace AsymmetricEncryptionNet.Services
{
    // Helper class to generate RSA keys
    public class RsaKeyGenerator
    {
        private RSA Rsa { get; }

        public RsaKeyGenerator()
        {
            Rsa = RSA.Create(2048);
        }

        public string PrivateKeyPEM()
        {         
            return Rsa.ExportPkcs8PrivateKeyPem();
        }

        public string PublicKeyPem()
        {
            return Rsa.ExportRSAPublicKeyPem();

        }

    }
}





