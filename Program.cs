using AsymmetricEncryptionNet.Services;

RsaKeyGenerator rsaKeyGenerator = new();

JwtTokenManager jWTTokenManager = new(rsaKeyGenerator.PrivateKeyPEM());



Console.WriteLine("Token: " + jWTTokenManager.Token);

Console.WriteLine("Token plain text: " + jWTTokenManager.DecodeToken());  

Console.WriteLine("Public key: " + rsaKeyGenerator.PublicKeyPem());

Console.WriteLine("Token is valid: " + jWTTokenManager.ValidateToken());