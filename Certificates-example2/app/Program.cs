using System.Formats.Asn1;
using System.Net.Mime;
using System.Runtime.InteropServices.Marshalling;
using System.Security.Cryptography.X509Certificates;
using System.Text;

var store = new X509Store(StoreLocation.CurrentUser);
store.Open(OpenFlags.ReadOnly);
foreach (var cert in store.Certificates)
{
    Console.WriteLine("-----------------------------");
    Console.WriteLine($"        Subject: {cert.Subject}");
    Console.WriteLine($"         Issuer: {cert.Issuer}");
    Console.WriteLine($"          Valid: {cert.NotBefore} - {cert.NotAfter}");
    Console.WriteLine($"     Thumbprint: {cert.Thumbprint}");
    Console.WriteLine($"  Serial number: {cert.SerialNumber}");
    Console.WriteLine($"     Extensions:");
    foreach (var ext in cert.Extensions)
    {
        Console.WriteLine($"\t\t({ext.Oid.Value}) {ext.Oid.FriendlyName}");
        switch (ext)
        {
            case X509BasicConstraintsExtension:
            {
                var x = (X509BasicConstraintsExtension)ext;
                Console.WriteLine($"\t\t   Is CA: {x.CertificateAuthority}");
                if (x.HasPathLengthConstraint)
                {
                    Console.WriteLine($"\t\t   PathLengthConstraint: {x.PathLengthConstraint}");
                }
                break;
            }
            case X509KeyUsageExtension:
            {
                var x = (X509KeyUsageExtension)ext;
                if (x.KeyUsages.HasFlag(X509KeyUsageFlags.EncipherOnly)){Console.WriteLine($"\t\t   EncipherOnly");}
                if (x.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign)){Console.WriteLine($"\t\t   CrlSign");}
                if (x.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign)){Console.WriteLine($"\t\t   KeyCertSign");}
                if (x.KeyUsages.HasFlag(X509KeyUsageFlags.KeyAgreement)){Console.WriteLine($"\t\t   KeyAgreement");}
                if (x.KeyUsages.HasFlag(X509KeyUsageFlags.DataEncipherment)){Console.WriteLine($"\t\t   DataEncipherment");}
                if (x.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)){Console.WriteLine($"\t\t   KeyEncipherment");}
                if (x.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation)){Console.WriteLine($"\t\t   NonRepudiation");}
                if (x.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)){Console.WriteLine($"\t\t   DigitalSignature");}
                if (x.KeyUsages.HasFlag(X509KeyUsageFlags.DecipherOnly)){Console.WriteLine($"\t\t   DecipherOnly");}
                break;
            }
            case X509EnhancedKeyUsageExtension:
            {
                var x = (X509EnhancedKeyUsageExtension)ext;
                foreach (var oid in x.EnhancedKeyUsages)
                {
                    if (!string.IsNullOrWhiteSpace(oid.FriendlyName))
                    {
                        Console.WriteLine($"\t\t   {oid.FriendlyName}");
                    }
                    else if(!string.IsNullOrWhiteSpace(OidToName(oid.Value)))
                    {
                        Console.WriteLine($"\t\t   {OidToName(oid.Value)}");
                    }
                    else
                    {
                        Console.WriteLine($"\t\t   {oid.Value}");
                    }
                }
                break;
            }
            case X509SubjectAlternativeNameExtension:
            {
                var x = (X509SubjectAlternativeNameExtension)ext;
                Console.WriteLine($"\t\t   {x.Format(false)}"); 
                break;
            }
            case X509AuthorityInformationAccessExtension:
            {
                var x = (X509AuthorityInformationAccessExtension)ext;
                foreach (var u in x.EnumerateOcspUris())
                {
                    Console.WriteLine($"\t\t   OCSP: {u}"); 
                }
                foreach (var u in x.EnumerateCAIssuersUris())
                {
                    Console.WriteLine($"\t\t   CAIssuer: {u}"); 
                }
                break;
            }
            case X509SubjectKeyIdentifierExtension:
            {
                var x = (X509SubjectKeyIdentifierExtension)ext;
                Console.WriteLine($"\t\t   SubjectKeyIdentifier: {x.SubjectKeyIdentifier}");
                break;
            }
            case X509AuthorityKeyIdentifierExtension:
            {
                var x = (X509AuthorityKeyIdentifierExtension)ext;
                Console.WriteLine($"\t\t   RAW: {x.Format(false)}");
                break;
            }
            default:
            {
                switch (ext.Oid.Value)
                {
                    case "1.3.6.1.4.1.311.84.1.1":
                    {
                        Console.WriteLine($"\t\t   ASP.NET Core HTTPS development certificat");
                        break;
                    }
                    case "2.5.29.31":
                    {
                        Console.WriteLine($"\t\t   CRL Distribution Points");
                        break;
                    }
                    case "2.5.29.32":
                    {
                        Console.WriteLine($"\t\t   Certificate Policies");
                        break;
                    }
                    case "2.5.29.18":
                    {
                        Console.WriteLine($"\t\t   Issuer alternative name");
                        break;
                    }
                    case "2.16.840.1.113730.1.1":
                    {
                        Console.WriteLine($"\t\t   Netscape certificate type");
                        break;
                    }
                    default:
                    {
                        Console.WriteLine($"\t\t   Type: {ext.GetType()}");
                        break;
                    }
                }
                
                break;
            }
        }
    }
}

string? OidToName(string oid)
{
    switch (oid)
    {
        case "1.3.6.1.5.5.7.3.1": return "serverAuth";
        case "1.3.6.1.5.5.7.3.2": return "clientAuth";
        case "1.3.6.1.5.5.7.3.3": return "codeSigning";
        case "1.3.6.1.5.5.7.3.4": return "emailProtection";
        case "1.3.6.1.5.5.7.3.5": return "ipsecEndSystem";
        case "1.3.6.1.5.5.7.3.6": return "ipsecTunnel";
        case "1.3.6.1.5.5.7.3.7": return "ipsecUser";
        case "1.3.6.1.5.5.7.3.8": return "timeStamping";
        case "1.3.6.1.5.5.7.3.9": return "ocspSigning";
        case "1.3.6.1.5.5.7.3.10": return "dvcs";
        case "1.3.6.1.5.5.7.3.13": return "id-kp-eapOverPPP";
        case "1.3.6.1.5.5.7.3.14": return "id-kp-eapOverLAN";
        case "1.3.6.1.5.5.7.3.15": return "id-kp-scvpServer";
        case "1.3.6.1.5.5.7.3.16": return "id-kp-scvpClient";
        case "1.3.6.1.5.5.7.3.17": return "id-kp-ipsecIKE";
        case "1.3.6.1.5.5.7.3.19": return "id-kp-capwapWTP";
        case "1.3.6.1.5.5.7.3.20": return "id-kp-sipDomain";
        case "1.3.6.1.5.5.7.3.21": return "secureShellClient";
        case "1.3.6.1.5.5.7.3.22": return "secureShellServer";
        case "1.3.6.1.5.5.7.3.27": return "id-kp-cmcCA";
        case "1.3.6.1.5.5.7.3.28": return "id-kp-cmcRA";
        case "1.3.6.1.5.5.7.3.29": return "id-kp-cmcArchive";
        default:
        {
            return null;
        }
    }
}