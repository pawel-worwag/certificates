using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Example3;

public static class Helpers
{
    public static string Format(this X509Certificate cert)
    {
        var sr = new StringBuilder();
        sr.AppendLine($"Version:                 {cert.Version}");
        sr.AppendLine($"SerialNumber:            {cert.SerialNumber}");
        sr.AppendLine($"SignatureAlgorithm:      {GetSignatureAlgorithmName(cert.SignatureAlgorithm.Algorithm.GetID())}");
        sr.AppendLine($"Issuer:                  {cert.IssuerDN}");
        sr.AppendLine($"Validity: ");
        sr.AppendLine($"   NotBefore:            {cert.NotBefore:R}");
        sr.AppendLine($"   NotAfter :            {cert.NotAfter:R}");
        sr.AppendLine($"Subject:                 {cert.SubjectDN}");
        sr.AppendLine($"Key usage: ");
        sr.AppendLine($"Subject Public Key Info:");
        sr.AppendLine($"PublicKeyAlgorithm:      {GetSignatureAlgorithmName(cert.SubjectPublicKeyInfo.Algorithm.Algorithm.GetID())}");
        sr.AppendLine($"X509v3 extensions:");
        
        var oids = cert.GetCriticalExtensionOids();
        var extensions = new List<Extension>();
        foreach (var oid in oids)
        {
           extensions.Add(new Extension()
           {
               Oid = oid,
               Critical = true,
               Value = cert.GetExtensionValue(new DerObjectIdentifier(oid))
           }); 
        }

        oids = cert.GetNonCriticalExtensionOids();
        foreach (var oid in oids)
        {
            extensions.Add(new Extension()
            {
                Oid = oid,
                Critical = false,
                Value = cert.GetExtensionValue(new DerObjectIdentifier(oid))
            }); 
        }

        extensions = extensions.OrderBy(p => p.Oid).ToList();
        foreach (var ext in extensions)
        {
            sr.AppendLine($"   {GetCertificateExtensionName(ext.Oid)}:");
            sr.AppendLine($"      Oid:               {ext.Oid}");
            sr.AppendLine($"      Critical:          {ext.Critical}");
            var details = ParseExtension(ext.Oid,ext.Value);
            if (!string.IsNullOrWhiteSpace(details))
            {
                sr.Append(details);
            }
        }
        return sr.ToString();
    }

    private static string? ParseExtension(string oid, Asn1Encodable value)
    {
        return oid switch
        {
            "2.5.29.15" => ParseKeyUsage(value),
            "2.5.29.19" => ParseBasicConstraints(value),
            "2.5.29.37" => ParseExtendedKeyUsage(value),
            _ => null
        };
    }

    private static string ParseExtendedKeyUsage(Asn1Encodable value)
    {
        var data = Asn1OctetString.GetInstance(value);
        var ext = new X509EnhancedKeyUsageExtension(new AsnEncodedData(data.GetOctets()), false);
        
        var sr = new StringBuilder();
        var list = new List<string>();
        foreach (var oid in ext.EnhancedKeyUsages)
        {
            list.Add(GetExtendedKeyPurposesName(oid.Value));
        }
        sr.AppendLine($"      Value:             {string.Join(", ",list)}");
        
        
        return sr.ToString();
    }
    
    private static string ParseBasicConstraints(Asn1Encodable value)
    {
        var sr = new StringBuilder();
        var data = Asn1OctetString.GetInstance(value);
        var ext = new X509BasicConstraintsExtension(new AsnEncodedData(data.GetOctets()),false);
        sr.AppendLine($"      CA:                {ext.CertificateAuthority}");
        sr.AppendLine($"      PathLength:        {ext.PathLengthConstraint}");
        return sr.ToString();
    }
    
    private static string ParseKeyUsage(Asn1Encodable value)
    {
        var data = Asn1OctetString.GetInstance(value);
        var ext = new X509KeyUsageExtension(new AsnEncodedData(data.GetOctets()), false);
        
        var sr = new StringBuilder();
        sr.AppendLine($"      Value:             {ext.KeyUsages}");
        
        
        return sr.ToString();
    }
    
    /*
    private static ICollection<string> ParseKeyUsage(bool[]? usage)
    {
        
           KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1),
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }
        
        var list = new List<string>();
        if (usage is null) return list;
        try
        {
        if(usage[0]){list.Add("digitalSignature");}
        if(usage[1]){list.Add("nonRepudiation");}
        if(usage[2]){list.Add("keyEncipherment");}
        if(usage[3]){list.Add("dataEncipherment");}
        if(usage[4]){list.Add("keyAgreement");}
        if(usage[5]){list.Add("keyCertSign");}
        if(usage[6]){list.Add("cRLSign");}
        if(usage[7]){list.Add("encipherOnly");}
        if(usage[8]){list.Add("decipherOnly");}
        }
        catch
        {
            // ignored
        }

        ;
        return list;
    }
    */
    private static string GetCertificateExtensionName(string oid)
    {
        return oid switch
        {
            "2.5.29.1" => "authorityKeyIdentifier",
            "2.5.29.2" => "keyAttributes",
            "2.5.29.3" => "certificatePolicies",
            "2.5.29.4" => "keyUsageRestriction",
            "2.5.29.5" => "policyMapping",
            "2.5.29.6" => "subtreesConstraint",
            "2.5.29.7" => "subjectAltName",
            "2.5.29.8" => "issuerAltName",
            "2.5.29.9" => "subjectDirectoryAttributes",
            "2.5.29.10" => "basicConstraints",
            "2.5.29.11" => "11",
            "2.5.29.12" => "12",
            "2.5.29.13" => "13",
            "2.5.29.14" => "subjectKeyIdentifier",
            "2.5.29.15" => "keyUsage",
            "2.5.29.16" => "privateKeyUsagePeriod",
            "2.5.29.17" => "subjectAltName",
            "2.5.29.18" => "issuerAltName",
            "2.5.29.19" => "basicConstraints",
            "2.5.29.20" => "cRLNumber",
            "2.5.29.21" => "reasonCode",
            "2.5.29.22" => "expirationDate",
            "2.5.29.23" => "instructionCode",
            "2.5.29.24" => "invalidityDate",
            "2.5.29.25" => "cRLDistributionPoints",
            "2.5.29.26" => "issuingDistributionPoint",
            "2.5.29.27" => "deltaCRLIndicator",
            "2.5.29.28" => "issuingDistributionPoint",
            "2.5.29.29" => "certificateIssuer",
            "2.5.29.30" => "nameConstraints",
            "2.5.29.31" => "cRLDistributionPoints",
            "2.5.29.32" => "certificatePolicies",
            "2.5.29.33" => "policyMappings",
            "2.5.29.34" => "policyConstraints",
            "2.5.29.35" => "authorityKeyIdentifier",
            "2.5.29.36" => "policyConstraints",
            "2.5.29.37" => "extKeyUsage",
            "2.5.29.38" => "authorityAttributeIdentifier",
            "2.5.29.39" => "roleSpecCertIdentifier",
            "2.5.29.40" => "cRLStreamIdentifier",
            "2.5.29.41" => "basicAttConstraints",
            "2.5.29.42" => "delegatedNameConstraints",
            "2.5.29.43" => "timeSpecification",
            "2.5.29.44" => "cRLScope",
            "2.5.29.45" => "statusReferrals",
            "2.5.29.46" => "freshestCRL",
            "2.5.29.47" => "orderedList",
            "2.5.29.48" => "attributeDescriptor",
            "2.5.29.49" => "userNotice",
            "2.5.29.50" => "sOAIdentifier",
            "2.5.29.51" => "baseUpdateTime",
            "2.5.29.52" => "acceptableCertPolicies",
            "2.5.29.53" => "deltaInfo",
            "2.5.29.54" => "inhibitAnyPolicy",
            "2.5.29.55" => "targetInformation",
            "2.5.29.56" => "noRevAvail",
            "2.5.29.57" => "acceptablePrivilegePolicies",
            "2.5.29.58" => "id-ce-toBeRevoked",
            "2.5.29.59" => "id-ce-RevokedGroups",
            "2.5.29.60" => "id-ce-expiredCertsOnCRL",
            "2.5.29.61" => "indirectIssuer",
            "2.5.29.62" => "id-ce-noAssertion",
            "2.5.29.63" => "id-ce-aAissuingDistributionPoint",
            "2.5.29.64" => "id-ce-issuedOnBehaIFOF",
            "2.5.29.65" => "id-ce-singleUse",
            "2.5.29.66" => "id-ce-groupAC",
            "2.5.29.67" => "id-ce-allowedAttAss",
            "2.5.29.68" => "id-ce-attributeMappings",
            "2.5.29.69" => "id-ce-holderNameConstraints",
            _ => oid
        };
    }
    
    private static string GetSignatureAlgorithmName(string oid)
    {
        return oid switch
        {
            "1.2.840.113549.1.1.1" => "rsaEncryption",
            "1.2.840.113549.1.1.2" => "md2WithRSAEncryption",
            "1.2.840.113549.1.1.3" => "md4withRSAEncryption",
            "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
            "1.2.840.113549.1.1.5" => "sha1-with-rsa-signature",
            "1.2.840.113549.1.1.6" => "rsaOAEPEncryptionSET",
            "1.2.840.113549.1.1.7" => "id-RSAES-OAEP",
            "1.2.840.113549.1.1.8" => "id-mgf1",
            "1.2.840.113549.1.1.9" => "id-pSpecified",
            "1.2.840.113549.1.1.10" => "rsassa-pss",
            "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
            "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
            "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
            "1.2.840.113549.1.1.14" => "sha224WithRSAEncryption",
            _ => $"Unknown ({oid})"
        };
    }

    private static string GetExtendedKeyPurposesName(string oid)
    {
        return oid switch
        {
            "1.3.6.1.5.5.7.3.1" => "serverAuth",
            "1.3.6.1.5.5.7.3.2" => "clientAuth",
            "1.3.6.1.5.5.7.3.3" => "codeSigning",
            "1.3.6.1.5.5.7.3.4" => "emailProtection",
            "1.3.6.1.5.5.7.3.5" => "ipsecEndSystem",
            "1.3.6.1.5.5.7.3.6" => "ipsecTunnel",
            "1.3.6.1.5.5.7.3.7" => "ipsecUser",
            "1.3.6.1.5.5.7.3.8" => "timeStamping",
            "1.3.6.1.5.5.7.3.9" => "ocspSigning",
            "1.3.6.1.5.5.7.3.10" => "dvcs",
            "1.3.6.1.5.5.7.3.11" => "sbgpCertAAServerAuth",
            "1.3.6.1.5.5.7.3.12" => "id-kp-scvp-responder",
            "1.3.6.1.5.5.7.3.13" => "id-kp-eapOverPPP",
            "1.3.6.1.5.5.7.3.14" => "id-kp-eapOverLAN",
            "1.3.6.1.5.5.7.3.15" => "id-kp-scvpServer",
            "1.3.6.1.5.5.7.3.16" => "id-kp-scvpClient",
            "1.3.6.1.5.5.7.3.17" => "id-kp-ipsecIKE",
            "1.3.6.1.5.5.7.3.18" => "id-kp-capwapAC",
            "1.3.6.1.5.5.7.3.19" => "id-kp-capwapWTP",
            "1.3.6.1.5.5.7.3.20" => "id-kp-sipDomain",
            "1.3.6.1.5.5.7.3.21" => "secureShellClient",
            "1.3.6.1.5.5.7.3.22" => "secureShellServer",
            "1.3.6.1.5.5.7.3.23" => "id-kp-sendRouter",
            "1.3.6.1.5.5.7.3.24" => "id-kp-sendProxy",
            "1.3.6.1.5.5.7.3.25" => "id-kp-sendOwner",
            "1.3.6.1.5.5.7.3.26" => "id-kp-sendProxiedOwner",
            "1.3.6.1.5.5.7.3.27" => "id-kp-cmcCA",
            "1.3.6.1.5.5.7.3.28" => "id-kp-cmcRA",
            "1.3.6.1.5.5.7.3.29" => "id-kp-cmcArchive",
            _ => $"Unknown ({oid})"
        };
    }
    
    private record Extension
    {
        public string Oid { get; init; }
        public bool Critical { get; init; }
        public Asn1Encodable Value { get; init; }
    }
}

