using System;

namespace EncodeCore
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            string[] message = "hello world \n how are you?\nI am fine".Split('\n');
            string[] cypher = MyEncryptionClass.EncryptText(message, "Helloworld");
            string[] returnval = MyEncryptionClass.DecryptText(cypher, "Helloworld");
        }
    }
}
