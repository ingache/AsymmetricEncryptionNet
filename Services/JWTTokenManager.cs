using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Newtonsoft.Json;


namespace AsymmetricEncryptionNet.Services
{
    public class JwtTokenManager
    {
        private readonly string issuer = "SomeIssuer";
        private readonly string audience = "SomeAudience";


        private readonly RSA _rsa;
        public string Token { get; }
        public JwtTokenManager(string privateKeyPEM)
        {
            _rsa = RSA.Create();

            _rsa.ImportFromPem(privateKeyPEM);

            Token = GenerateToken();
        }

        public string DecodeToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            return tokenHandler.ReadJwtToken(Token).ToString(); 
        }

        public bool ValidateToken()
        {
            try
            {
                string publicKeyXml = _rsa.ToXmlString(false);

                // Create a new instance of RSA for the public key
                using var rsa = RSA.Create();

                rsa.FromXmlString(publicKeyXml); // Import the public key

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = issuer, // Replace with your issuer
                    ValidAudience = audience, // Replace with your audience
                    IssuerSigningKey = new RsaSecurityKey(rsa)
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.ValidateToken(Token, validationParameters, out var validatedToken);

                return validatedToken != null;
            }
            catch (Exception ex)
            {
                // Handle or log the exception as needed
                Console.WriteLine("Token validation failed: " + ex.Message);
                return false;
            }
        }

        private string GenerateToken()
        {
            var signingCredentials = new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "user_id"),
                // Add other claims as needed
            };

            var token = new JwtSecurityToken(
                 issuer: this.issuer,
                 audience: this.audience,
                 claims: claims,
                 expires: DateTime.UtcNow.AddDays(1),
                 signingCredentials: signingCredentials
               );

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }
    }
}






