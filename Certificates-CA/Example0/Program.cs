using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

SecureRandom random = new SecureRandom();
byte[] keyBytes = new byte[16];
random.NextBytes(keyBytes);
ICipherParameters keyParam = new KeyParameter(keyBytes);

string message = "Ala-ma-kota-i-psa123!";
var plaintextBytes = Encoding.UTF8.GetBytes(message);

Console.WriteLine($"Original message: \t\t'{message}'");

IBlockCipher blockCipher = new AesEngine();
IBlockCipherMode symmetricBlockMode = new EcbBlockCipher(blockCipher);
IBlockCipherPadding padding = new Pkcs7Padding();
PaddedBufferedBlockCipher ecbCipher = new PaddedBufferedBlockCipher(symmetricBlockMode, padding);

//Encrypt
ecbCipher.Init(true, keyParam);
int blockSize = ecbCipher.GetBlockSize();
byte[] cipherTextData = new byte[ecbCipher.GetOutputSize(plaintextBytes.Length)]; 
int processLength = ecbCipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, cipherTextData, 0);
int finalLength = ecbCipher.DoFinal(cipherTextData, processLength);
byte[] finalCipherTextData = new byte[cipherTextData.Length - (blockSize - finalLength)];
Array.Copy(cipherTextData,0,finalCipherTextData,0,finalCipherTextData.Length);

Console.WriteLine($"Encrypted message: \t\t'{Encoding.UTF8.GetString(finalCipherTextData)}'");
Console.WriteLine($"Encrypted message base64: \t'{Convert.ToBase64String(finalCipherTextData)}'");

//Decrypt
ecbCipher.Init(false, keyParam);
blockSize = ecbCipher.GetBlockSize();
byte[] plainTextData = new byte[ecbCipher.GetOutputSize(finalCipherTextData.Length)];
ecbCipher.ProcessBytes(finalCipherTextData, 0, finalCipherTextData.Length, plainTextData, 0);
finalLength = ecbCipher.DoFinal(plainTextData, processLength);
byte[] finalPlainTextData = new byte[plainTextData.Length - (blockSize - finalLength)]; 
Array.Copy(plainTextData,0,finalPlainTextData,0,finalPlainTextData.Length);


Console.WriteLine($"Decrypted message: \t\t'{Encoding.UTF8.GetString(finalPlainTextData)}'");
