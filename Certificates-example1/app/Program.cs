using System.Security.Cryptography.X509Certificates;

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
}