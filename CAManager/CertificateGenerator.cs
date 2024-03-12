using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CAManager
{

    public class CertificateGenerator
    {
        public void GenerateCertificates()
        {
            string[] ipAddresses = { "192.168.0.101", "10.0.0.1" };

            // 生成根证书
            AsymmetricCipherKeyPair rootKeyPair = GenerateKeyPair();
            X509Certificate rootCert = GenerateRootCertificate(rootKeyPair, "CN=Root CA", ipAddresses);

            // 生成客户端证书
            AsymmetricCipherKeyPair clientKeyPair = GenerateKeyPair();
            X509Certificate clientCert = GenerateCertificate(clientKeyPair, rootCert, rootKeyPair.Private, "CN=Client", ipAddresses);

            // 生成服务端证书
            AsymmetricCipherKeyPair serverKeyPair = GenerateKeyPair();
            X509Certificate serverCert = GenerateCertificate(serverKeyPair, rootCert, rootKeyPair.Private, "CN=Server", ipAddresses);

            // 将证书和私钥保存为PEM格式的文件
            // 将证书和私钥分别保存为PEM格式的文件
            SaveToPem("bouncyCastle/ca.crt", "bouncyCastle/ca.key", rootCert, rootKeyPair.Private);
            SaveToPem("bouncyCastle/client.crt", "bouncyCastle/client.key", clientCert, clientKeyPair.Private);
            SaveToPem("bouncyCastle/server.crt", "bouncyCastle/server.key", serverCert, serverKeyPair.Private);
        }

        private AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 2048));

            return generator.GenerateKeyPair();
        }

        private X509Certificate GenerateRootCertificate(AsymmetricCipherKeyPair keyPair, string subject, string[] ipAddresses)
        {

            Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private, null);
            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetSerialNumber(BigInteger.ValueOf(DateTime.Now.Ticks));
            certGenerator.SetIssuerDN(new X509Name(subject));
            certGenerator.SetSubjectDN(new X509Name(subject));
            certGenerator.SetNotBefore(DateTime.UtcNow);
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));

            List<Asn1Encodable> asn1Encodables = new List<Asn1Encodable>();
            foreach (var ipAddress in ipAddresses)
            {
                asn1Encodables.Add(new GeneralName(GeneralName.IPAddress, ipAddress));
            }
            certGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new DerSequence(new Asn1EncodableVector([.. asn1Encodables])));
            certGenerator.SetPublicKey(keyPair.Public);
            var cert = certGenerator.Generate(signatureFactory);
            return cert;
        }

        private X509Certificate GenerateCertificate(AsymmetricCipherKeyPair keyPair, X509Certificate issuerCert, AsymmetricKeyParameter issuerKey, string subject, string[] ipAddresses)
        {
            Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", issuerKey, null);
            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetSerialNumber(BigInteger.ValueOf(DateTime.Now.Ticks));
            certGenerator.SetIssuerDN(issuerCert.SubjectDN);
            certGenerator.SetSubjectDN(new X509Name(subject));
            certGenerator.SetNotBefore(DateTime.UtcNow);
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
            certGenerator.SetPublicKey(keyPair.Public);
            List<Asn1Encodable> asn1Encodables = new List<Asn1Encodable>();
            foreach (var ipAddress in ipAddresses)
            {
                asn1Encodables.Add(new GeneralName(GeneralName.IPAddress, ipAddress));
            }
            certGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new DerSequence(new Asn1EncodableVector([.. asn1Encodables])));
            var cert = certGenerator.Generate(signatureFactory);
            return cert;
        }

        private void SaveToPem(string certFileName, string keyFileName, X509Certificate cert, AsymmetricKeyParameter key)
        {
            // 保存证书
            using (TextWriter certTW = File.CreateText(certFileName))
            {
                PemWriter certPemWriter = new PemWriter(certTW);
                certPemWriter.WriteObject(cert);
                certPemWriter.Writer.Flush();
            }

            // 保存私钥
            using (TextWriter keyTW = File.CreateText(keyFileName))
            {
                PemWriter keyPemWriter = new PemWriter(keyTW);
                keyPemWriter.WriteObject(key);
                keyPemWriter.Writer.Flush();
            }
        }


        public X509Certificate LoadBouncyCastleCertificate(string certFilePath)
        {
            // 读取Bouncy Castle生成的证书文件
            X509CertificateParser parser = new X509CertificateParser();
            X509Certificate bcCert = parser.ReadCertificate(File.ReadAllBytes(certFilePath));
            return bcCert;
        }
    }
}
