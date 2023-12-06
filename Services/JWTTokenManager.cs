using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Serialization;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.PortableExecutable;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AsymmetricEncryptionNet.Services
{
    public class JwtTokenManager
    {
        private readonly int keySize = 2048;

        // Define issuer and audience for the token
        private readonly string issuer = "SomeIssuer";
        private readonly string audience = "SomeAudience";

        // RSA instance for cryptographic operations
        private readonly RSA _rsa;
        
        // Publicly accessible property to get the generated token
        public string Token { get; set; }

        // Constructor that takes a private key in PEM format
        public JwtTokenManager(string privateKeyPEM)
        {
            // Initialize RSA and import the private key
            _rsa = RSA.Create(keySize);
            _rsa.ImportFromPem(privateKeyPEM);

            // Generate the JWT token
            Token = GenerateToken();
        }

        // Method to decode a JWT token into a readable format
        public string DecodeToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            // Returns the decoded JWT token as string
            return tokenHandler.ReadJwtToken(Token).ToString(); 
        }

        // Validates the JWT token using a public key in PEM format
        public bool ValidateToken(string publicKeyPEM)
        {
            try
            {
                // Create a new instance of RSA for the public key
                var rsa = RSA.Create(keySize);
                rsa.ImportFromPem(publicKeyPEM);

                // Set up token validation parameters
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = issuer, 
                    ValidAudience = audience, 
                    IssuerSigningKey = new RsaSecurityKey(rsa)
                    {
                        CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
                    }
                };

                // Create a token handler for validation
                var tokenHandler = new JwtSecurityTokenHandler();
                // Validate the token
                tokenHandler.ValidateToken(Token, validationParameters, out var validatedToken);
                
                DateTime validTo = tokenHandler.ReadJwtToken(Token).ValidTo.ToUniversalTime();
                DateTime now = DateTime.UtcNow;

                Console.WriteLine("Token Valid to: " + validTo);
                Console.WriteLine("Current time:   " + now);

                return ((DateTime.Compare(now, validTo) == -1 ) && (validatedToken != null));

            }
            catch (Exception ex)
            {
                // If validation fails, log the exception and return false
                Console.WriteLine("Token validation failed: " + ex.Message);
                return false;
            }
        }

        public void RegenerateToken()
        {

            // Generate the JWT token
            Token = GenerateToken();

        }

        // Generates a JWT token with specified claims and signing credentials
        private string GenerateToken()
        {
            //{
            //    CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            //};

            // Define the claims for the token
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "user_id"),
            };

            // Create the JWT token
            var token = new JwtSecurityToken(
                 issuer: this.issuer,
                 audience: this.audience,
                 claims: claims,
                 notBefore: DateTime.UtcNow,
                 expires: DateTime.UtcNow.AddSeconds(2),
                 signingCredentials: new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256)
            );

            var tokenStr = new JwtSecurityTokenHandler().WriteToken(token);

            return tokenStr;
        }
    }
}
