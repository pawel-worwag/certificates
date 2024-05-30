using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Example4;

public static class Utils
{
    
    public static AsymmetricCipherKeyPair? GenerateRsaKeyPair(int strength = 2048)
    {
        var secureRandom = new SecureRandom();
        var keygenParam = new KeyGenerationParameters(secureRandom, strength);
        var keyGenerator = new RsaKeyPairGenerator();
        keyGenerator.Init(keygenParam);
        return keyGenerator.GenerateKeyPair();
    }

    public static X509Certificate? CreateCertificate(
        BigInteger serialNumber,
        string subject, 
        string issuer,
        AsymmetricKeyParameter subjectPublicKey, 
        DateTime validNotBefore,
        DateTime validNotAfter,
        IList<Extension> extensions,
        string signatureAlgorithm, 
        AsymmetricKeyParameter issuerKey)
    {
        var x509Subject = new X509Name(subject);
        var x509Issuer = new X509Name(issuer);
        
        var certGenerator = new X509V3CertificateGenerator();
        
        
        certGenerator.SetSerialNumber(serialNumber);
        certGenerator.SetNotBefore(validNotBefore);
        certGenerator.SetNotAfter(validNotAfter);
        
        certGenerator.SetSubjectDN(x509Subject);
        
        certGenerator.SetIssuerDN(x509Issuer);
        certGenerator.SetPublicKey(subjectPublicKey);

        foreach (var ext in extensions)
        {
            certGenerator.AddExtension(ext.Oid,ext.Critical,ext.Value);
        }
        
        var signatureFactory = new Asn1SignatureFactory(signatureAlgorithm,issuerKey);
        return certGenerator.Generate(signatureFactory);
    }
}

public record Extension
{
    public required DerObjectIdentifier Oid { get; init; }
    public required bool Critical { get; init; }
    public required Asn1Encodable Value { get; init; }
}