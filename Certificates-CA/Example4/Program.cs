using System.Security.Cryptography.X509Certificates;
using Example4;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security.Certificates;

var caKeyPair = Utils.GenerateRsaKeyPair();
var caAlgorithm = PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString();
var caSubject = "CN=TEST CA";
var caIssuer = "CN=TEST CA";

//generate CA
var caExtensions = new List<Extension>();

caExtensions.Add(new Extension()
{
    Oid = X509Extensions.BasicConstraints,
    Critical = true,
    Value = new BasicConstraints(10)
});

caExtensions.Add(new Extension()
{
    Oid = X509Extensions.KeyUsage,
    Critical = true,
    Value = new KeyUsage(KeyUsage.CrlSign|KeyUsage.KeyCertSign)
});



var certificate = Utils.CreateCertificate(
    BigInteger.ValueOf(1), 
    caSubject, 
    caIssuer, 
    caKeyPair.Public, 
    DateTime.UtcNow, 
    DateTime.UtcNow.AddHours(1),
    caExtensions,
    caAlgorithm, 
    caKeyPair.Private);

using (var f = File.OpenWrite("ca.cer"))
{
    var buf = certificate.GetEncoded();
    f.Write(buf, 0, buf.Length);
}



//Generate End-cert
var endKeyPair = Utils.GenerateRsaKeyPair();
var endAlgorithm = PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString();
var endSubject = "CN=Jan Nieznany";
var endIssuer = "CN=TEST CA";

var endExtensions = new List<Extension>();

endExtensions.Add(new Extension()
{
    Oid = X509Extensions.BasicConstraints,
    Critical = true,
    Value = new BasicConstraints(false)
});

endExtensions.Add(new Extension()
{
    Oid = X509Extensions.KeyUsage,
    Critical = true,
    Value = new KeyUsage(KeyUsage.DigitalSignature|KeyUsage.DataEncipherment)
});

endExtensions.Add(new Extension()
{
    Oid = X509Extensions.ExtendedKeyUsage,
    Critical = false,
    Value = new ExtendedKeyUsage([
        KeyPurposeID.id_kp_clientAuth, KeyPurposeID.id_kp_emailProtection ])
});

//AltNames
var altNames = new List<GeneralName> { new GeneralName(GeneralName.Rfc822Name, "user@example.com") };

endExtensions.Add(new Extension()
{
    Oid = X509Extensions.SubjectAlternativeName,
    Critical = false,
    Value = new GeneralNames(altNames.ToArray())
});

//Policy
var list = new List<Asn1Encodable>()
{
    PolicyQualifierInfo.GetInstance(new DerSequence(new Asn1EncodableVector()
    {
        PolicyQualifierID.IdQtCps,
        new DerIA5String("http://example.com")
    })),
};

var policyInformations = new List<PolicyInformation>
{
    new PolicyInformation(new DerObjectIdentifier("2.23.140.1.5.1.2"),new DerSequence(list.ToArray()))
};

endExtensions.Add(new Extension()
{
    Oid = X509Extensions.CertificatePolicies,
    Critical = false,
    Value = new CertificatePolicies(policyInformations.ToArray())
});


//CRL

var crlNames = new List<GeneralName> { 
    new GeneralName(GeneralName.UniformResourceIdentifier, "http://www.example.com"),
    new GeneralName(GeneralName.UniformResourceIdentifier, "http://www.example2.com") 
};
var crlList = new List<DistributionPoint>();
crlList.Add(new DistributionPoint(
    new DistributionPointName(new GeneralNames(crlNames.ToArray())),null,null
)
);

endExtensions.Add(new Extension()
{
    Oid = X509Extensions.CrlDistributionPoints,
    Critical = false,
    Value = new CrlDistPoint(crlList.ToArray())
});

//Create cert

var endCertificate = Utils.CreateCertificate(
    BigInteger.ValueOf(1), 
    endSubject, 
    endIssuer, 
    endKeyPair.Public, 
    DateTime.UtcNow, 
    DateTime.UtcNow.AddHours(1),
    endExtensions,
    endAlgorithm, 
    caKeyPair.Private);

using (var f = File.OpenWrite("end.cer"))
{
    var buf = endCertificate.GetEncoded();
    f.Write(buf, 0, buf.Length);
}