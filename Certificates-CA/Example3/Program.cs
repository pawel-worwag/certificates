
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Example3;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.X509;
using X509BasicConstraintsExtension = System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension;

var keyPair = GenerateKeys();
var cert = GenerateSelfSignedCaCertificate(keyPair,"CN=TestC,OU=HQ,O=PWORWAG.COM.PL,C=PL",DateTime.UtcNow,DateTime.UtcNow.AddHours(1));

Console.WriteLine(cert.Format());
return;







X509Certificate? GenerateSelfSignedCaCertificate(AsymmetricCipherKeyPair keyPair, string subject, DateTime notBefore, DateTime notAfter)
{
    var x509Subject = new X509Name(subject);
    var certGenerator = new X509V3CertificateGenerator();
    
    certGenerator.SetIssuerDN(x509Subject);
    certGenerator.SetSubjectDN(x509Subject);
    certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
    certGenerator.SetNotBefore(notBefore);
    certGenerator.SetNotAfter(notAfter);
    certGenerator.SetPublicKey(keyPair.Public);
    
    certGenerator.AddExtension(X509Extensions.BasicConstraints,true,new BasicConstraints(true));
    
    certGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.CrlSign|KeyUsage.KeyCertSign));
    
    certGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage([
    KeyPurposeID.id_kp_scvp_responder, KeyPurposeID.id_kp_dvcs ]));
    
    var signatureFactory = new Asn1SignatureFactory(
        PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
        keyPair.Private);
    return certGenerator.Generate(signatureFactory);
}

AsymmetricCipherKeyPair? GenerateKeys(int strength = 2048)
 {
     var secureRandom = new SecureRandom();
     var keygenParam = new KeyGenerationParameters(secureRandom, strength);
     var keyGenerator = new RsaKeyPairGenerator();
     keyGenerator.Init(keygenParam);
     return keyGenerator.GenerateKeyPair();
 }