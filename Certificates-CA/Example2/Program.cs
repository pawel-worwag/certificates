using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

var secureRandom = new SecureRandom();
var keygenParam = new KeyGenerationParameters(secureRandom, 2048);
var keyGenerator = new RsaKeyPairGenerator();
keyGenerator.Init(keygenParam);
var issuerKeys = keyGenerator.GenerateKeyPair();


var signatureFactory = new Asn1SignatureFactory(
    PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
    issuerKeys.Private);

var issuer = new X509Name("CN=TestCA");


var certGenerator = new X509V3CertificateGenerator();
certGenerator.SetIssuerDN(issuer);
certGenerator.SetSubjectDN(issuer);
certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
certGenerator.SetNotAfter(DateTime.UtcNow.AddHours(1));
certGenerator.SetNotBefore(DateTime.UtcNow);
certGenerator.SetPublicKey(issuerKeys.Public);
certGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true,
    new ExtendedKeyUsage(new List<DerObjectIdentifier>() { KeyPurposeID.AnyExtendedKeyUsage}));

var cert = certGenerator.Generate(signatureFactory);

using (var f = File.OpenWrite("ca.cer"))
{
    var buf = cert.GetEncoded();
    f.Write(buf, 0, buf.Length);
}