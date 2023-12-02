using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
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
        public string Token { get; }

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
                };

                // Create a token handler for validation
                var tokenHandler = new JwtSecurityTokenHandler();
                // Validate the token
                tokenHandler.ValidateToken(Token, validationParameters, out var validatedToken);

                // Return true if token is valid, false otherwise
                return validatedToken != null;
            }
            catch (Exception ex)
            {
                // If validation fails, log the exception and return false
                Console.WriteLine("Token validation failed: " + ex.Message);
                return false;
            }
        }

        // Generates a JWT token with specified claims and signing credentials
        private string GenerateToken()
        {
            // Set up the signing credentials using RSA
            var signingCredentials = new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256);

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
                 expires: DateTime.UtcNow.AddDays(1),
                 signingCredentials: signingCredentials
            );

            // Create a token handler and write the token
            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }
    }
}
