using AsymmetricEncryptionNet.Services;

RsaKeyGenerator rsaKeyGenerator = new();

JwtTokenManager jWTTokenManager = new(rsaKeyGenerator.GetPrivateKeyPEM());



Console.WriteLine("Token: " + jWTTokenManager.Token);

Console.WriteLine("Token plain text: " + jWTTokenManager.DecodeToken());  

Console.WriteLine("Public key: " + rsaKeyGenerator.GetPublicKeyPem());

Console.WriteLine("Token is valid: " + jWTTokenManager.ValidateToken(rsaKeyGenerator.GetPublicKeyPem()));