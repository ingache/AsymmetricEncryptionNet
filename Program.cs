using AsymmetricEncryptionNet.Services;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.KeyVault;

bool enableVault = false;

if (enableVault)
{
    string clientId = "SOME_CLIENT_ID";
    string clientSecret = "SOME_CLIENT_SECRET";
    string tenantId = "SOME_TENANT";
    string keyVaultUrl = "SOME_VAULT_ENDPOINT";

    var publicKeySecretName = "JwtPublicKeyPem";
    var privateKeySecretName = "JwtPrivateKeyPem";

    var client = new SecretClient(
        new Uri(keyVaultUrl),
        new ClientSecretCredential(tenantId, clientId, clientSecret));

    KeyVaultSecret publicSecret = client.GetSecret(publicKeySecretName);

    KeyVaultSecret privateSecret = client.GetSecret(privateKeySecretName);

    JwtTokenManager jWTTokenManager = new(privateSecret.Value);

    Console.WriteLine("Token: " + jWTTokenManager.Token);

    Console.WriteLine("Token plain text: " + jWTTokenManager.DecodeToken());

    Console.WriteLine("Token is valid: " + jWTTokenManager.ValidateToken(publicSecret.Value));
}
else {
    RsaKeyGenerator rsaKeyGenerator = new();

    JwtTokenManager jWTTokenManager = new(rsaKeyGenerator.GetPrivateKeyPEM());

    Console.WriteLine("Token: " + jWTTokenManager.Token);
    Console.WriteLine("Token: " + jWTTokenManager.Token);

    Console.WriteLine("Token plain text: " + jWTTokenManager.DecodeToken());

    Console.WriteLine("Private key: " + rsaKeyGenerator.GetPrivateKeyPEM());

    Console.WriteLine("Public key: " + rsaKeyGenerator.GetPublicKeyPem());

    Console.WriteLine("Token is valid: " + jWTTokenManager.ValidateToken(rsaKeyGenerator.GetPublicKeyPem()));
    Console.WriteLine("Token is valid: " + jWTTokenManager.ValidateToken(rsaKeyGenerator.GetPublicKeyPem()));

    Aes256KeyGenerator aes256KeyGenerator = new();

    Console.WriteLine("AES Key: " + aes256KeyGenerator.Key);
    Console.WriteLine("AES IV: " + aes256KeyGenerator.IV);
}











