namespace CAManager
{
    internal class Program
    {
        static void Main(string[] args)
        {
            new CertificateGenerator().GenerateCertificates();

            Console.WriteLine("证书生成成功!");
            Console.ReadKey();
        }
    }
}
