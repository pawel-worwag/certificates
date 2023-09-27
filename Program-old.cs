
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

RSA key = RSA.Create(4096);
var builder = new X500DistinguishedNameBuilder();
builder.AddCommonName("pworwag.com.pl ecample ca");
builder.AddCountryOrRegion("PL");
builder.AddOrganizationName("U4");
builder.AddStateOrProvinceName("Łódzkie");

CertificateRequest req = new CertificateRequest(
    builder.Build(),
    key,
    HashAlgorithmName.SHA512,
    RSASignaturePadding.Pkcs1);

req.CertificateExtensions.Add( 
    new X509BasicConstraintsExtension(true,false,0,true
    ));  
req.CertificateExtensions.Add(
    new X509SubjectKeyIdentifierExtension(req.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha1,false));    
req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));

var info = new X509AuthorityInformationAccessExtension(new List<string>(){"http://oscp.u4.local"},new List<string>(){"http://u4.local/ca.crt"},false);
req.CertificateExtensions.Add(info);

//req.CertificateExtensions.Add(cdpExtension);


X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-45),
    DateTimeOffset.UtcNow.AddDays(365));

var certData = cert.Export(X509ContentType.Pkcs12,"12345");
File.WriteAllBytes("cert.pfx", certData);

var pemData = cert.ExportCertificatePem();
File.WriteAllText("cert.pem", pemData);

var keyData = key.ExportEncryptedPkcs8PrivateKeyPem("12345",new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,HashAlgorithmName.SHA1, 1024));
File.WriteAllText("cert.key", keyData);