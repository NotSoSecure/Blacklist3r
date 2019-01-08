using CommandLine;
using System;

namespace NotSoSecure.AspDotNetWrapper
{
    class Options
    {
        [Option('r', "keypath", Required = false, HelpText = "Machine keys file path.")]
        public string strKeysFilePath { get; set; }

        [Option('c', "cookie", Required = false, HelpText = "Cookie value to decrypt.")]
        public string strCookieValue { get; set; }

        [Option('d', "decrypt", Required = false, Default = false, HelpText = "To decrypt the cookie.")]
        public bool bDecrypt { get; set; }

        [Option('f', "decryptDataFilePath", Required = false, HelpText = "file path where the decrypted information stored")]
        public string strDecryptDataFilePath { get; set; }

        [Option('p', "purpose", Required = false, HelpText = "purpose")]
        public string strPurpose { get; set; }

        [Option('a', "valalgo", Required = false, HelpText = "Validation algorithm")]
        public string strValidationAlgorithm { get; set; }

        [Option('b', "decalgo", Required = false, HelpText = "Decryption algorithm")]
        public string strDecryptionAlgorithm { get; set; }

        [Option('o', "outputFile", Required = false, HelpText = "Output file path")]
        public string strOutputFilePath { get; set; }

        public static void GetUsage(bool bDecrypt)
        {
            if (bDecrypt)
            {
                Console.WriteLine("Required option missing!!");
                Console.WriteLine("-------------------------");
                Console.WriteLine("-r, --keypath Required keys file path.");
                Console.WriteLine("-c, --cookie Cookie value to decrypt.");
                Console.WriteLine("-p, --purpose Purpose of the cookie");
                Console.WriteLine("- d, --decrypt(Default: false) To decrypt the cookie.");
                Console.WriteLine("- a, --valalgo Validation algorithm.");
                Console.WriteLine("- b, --decalgo Decryption algorithm.");
                Console.WriteLine("--help Display this help screen.");
                Console.WriteLine("--version Display version information.");
            }
            else
            {
                Console.WriteLine("Required option missing!!");
                Console.WriteLine("-------------------------");
                Console.WriteLine("-f, --decryptDataFilePath    file path where the decrpted information stored");
                Console.WriteLine("--help Display this help screen.");
                Console.WriteLine("--version Display version information.");
            }
        }
    }
}
