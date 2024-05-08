using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

RsaKeyPairGenerator g = new RsaKeyPairGenerator();
g.Init(new KeyGenerationParameters(new SecureRandom(), 2048));

AsymmetricCipherKeyPair pair = g.GenerateKeyPair();


PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private);
byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded();
string serializedPrivate = Convert.ToBase64String(serializedPrivateBytes);

SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public);
byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
string serializedPublic = Convert.ToBase64String(serializedPublicBytes);


Console.WriteLine("private: ");
Console.WriteLine(serializedPrivate);
Console.WriteLine();
Console.WriteLine("public: ");
Console.WriteLine(serializedPublic);