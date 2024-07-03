using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

string message = "Ala-ma-kota-i-psa123!";
var plaintextBytes = Encoding.UTF8.GetBytes(message);
Console.WriteLine($"Original message: \t\t'{message}'");
var key = "12345678";
Console.WriteLine($"Key size: \t\t\t{key.Length}");
var encryptedData = encrypt(Encoding.UTF8.GetBytes(message), key);

Console.WriteLine($"Encrypted message: \t\t'{Encoding.UTF8.GetString(encryptedData)}'");
Console.WriteLine($"Encrypted message base64: \t'{Convert.ToBase64String(encryptedData)}'");

var decryptedData = decrypt(encryptedData, key);

Console.WriteLine($"Decrypted message: \t\t'{Encoding.UTF8.GetString(decryptedData)}'");
//Decrypt


byte[] encrypt(byte[] message, string password)
{
    byte[] keyBytes = Encoding.UTF8.GetBytes(password);
    ICipherParameters keyParam = new KeyParameter(keyBytes);

    IBlockCipher blockCipher = new DesEngine();
    IBlockCipherMode symmetricBlockMode = new CbcBlockCipher(blockCipher);
    IBlockCipherPadding padding = new Pkcs7Padding();
    PaddedBufferedBlockCipher cbcCipher = new PaddedBufferedBlockCipher(symmetricBlockMode, padding);
    cbcCipher.Init(true, keyParam);
    int blockSize = cbcCipher.GetBlockSize();
    byte[] cipherTextData = new byte[cbcCipher.GetOutputSize(plaintextBytes.Length)];
    int processLength = cbcCipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, cipherTextData, 0);
    int finalLength = cbcCipher.DoFinal(cipherTextData, processLength);
    byte[] finalCipherTextData = new byte[cipherTextData.Length - (blockSize - finalLength)]; 
    Array.Copy(cipherTextData,0, finalCipherTextData,0, finalCipherTextData.Length);
    return finalCipherTextData;
}

byte[] decrypt(byte[] message, string password)
{
    byte[] keyBytes = Encoding.UTF8.GetBytes(password);
    ICipherParameters keyParam = new KeyParameter(keyBytes);
    
    IBlockCipher symmetricBlockCipher = new DesEngine();
    IBlockCipherMode symmetricBlockMode = new CbcBlockCipher(symmetricBlockCipher); IBlockCipherPadding padding = new Pkcs7Padding();
    PaddedBufferedBlockCipher cbcCipher =
        new PaddedBufferedBlockCipher(symmetricBlockMode, padding);
    cbcCipher.Init(false, keyParam);
    int blockSize = cbcCipher.GetBlockSize();
    byte[] plainTextData = new byte[cbcCipher.GetOutputSize(message.Length)]; int processLength =
        cbcCipher.ProcessBytes(message, 0, message.Length, plainTextData, 0); int finalLength = cbcCipher.DoFinal(plainTextData, processLength);
    byte[] finalPlainTextData = new byte[plainTextData.Length - (blockSize - finalLength)]; Array.Copy(plainTextData,0, finalPlainTextData,0, finalPlainTextData.Length);
    return finalPlainTextData;
}