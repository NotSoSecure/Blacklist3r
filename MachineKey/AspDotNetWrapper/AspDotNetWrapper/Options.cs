using CommandLine;
using System;

namespace NotSoSecure.AspDotNetWrapper
{
    class Options
    {
        [Option('r', "keypath", Required = false, HelpText = "Machine keys file path.")]
        public string strKeysFilePath { get; set; }

        [Option('c', "encrypteddata", Required = false, HelpText = "Encrypted data value to decrypt.")]
        public string strEncryptedData { get; set; }

        [Option('d', "decrypt", Required = false, Default = false, HelpText = "To decrypt the encrypted data.")]
        public bool bDecrypt { get; set; }

        [Option('f', "decryptDataFilePath", Required = false, HelpText = "file path where the decrypted information stored")]
        public string strDecryptDataFilePath { get; set; }

        [Option('p', "purpose", Required = false, HelpText = "purpose")]
        public string strPurpose { get; set; }

        [Option('m', "modifier", Required = false, HelpText = "Modifier used to encode the viewstate")]
        public string strModifier { get; set; }

        [Option('s', "macdecode", Required = false, HelpText = "Used to decide whether viewstate is MAC enabled or not")]
        public bool bDecode { get; set; }

        [Option('o', "outputFile", Required = false, HelpText = "Output file path")]
        public string strOutputFilePath { get; set; }

        [Option('i', "IISDirPath", Required = false, HelpText = "Application dir path in IIS tree")]
        public string strIISDirPath { get; set; }

        [Option('t', "TargetPagePath", Required = false, HelpText = "Target page path")]
        public string strTargetPagePath { get; set; }

        [Option('v', "antiCSRFToken", Required = false, HelpText = "Anti CSRF token")]
        public string strAntiCSRFToken { get; set; }

        public static void GetUsage(bool bDecrypt)
        {
            if (bDecrypt)
            {
                Console.WriteLine("Required option missing!!");
                Console.WriteLine("-------------------------");
                Console.WriteLine("-r, --keypath Required keys file path.");
                Console.WriteLine("-c, --encrypteddata EncryptedData/FilePath(In which value is stored) to decrypt.");
                Console.WriteLine("-p, --purpose Purpose of the encrypteddata");
                Console.WriteLine("-d, --decrypt(Default: false) To decrypt the encrypteddata.");
                Console.WriteLine("-a, --valalgo Validation algorithm.");
                Console.WriteLine("-b, --decalgo Decryption algorithm.");
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

        //Usage for .net < 4.5
        public static void GetViewStateLegacyUsage()
        {
            Console.WriteLine("Required option missing!!");
            Console.WriteLine("-------------------------");
            Console.WriteLine("-r, --keypath Required keys file path.");
            Console.WriteLine("-c, --encrypteddata ViewStatedata/FilePath(In which value is stored) to decode or decrypt.");
            Console.WriteLine("-p, --purpose Purpose of the encrypteddata");
            Console.WriteLine("-a, --valalgo Validation algorithm.");
            Console.WriteLine("-b, --decalgo Decryption algorithm.");
            Console.WriteLine("-m, --modifier Modifier userd to encode the data.");
            Console.WriteLine("-s, --macdecode Used to decide whether the data needs to decode or not.");
        }

        //Usage for .net >= 4.5
        public static void GetViewStateUsage()
        {
            Console.WriteLine("Required option missing!!");
            Console.WriteLine("-------------------------");
            Console.WriteLine("-r, --keypath Required keys file path.");
            Console.WriteLine("-c, --encrypteddata ViewStatedata/FilePath(In which value is stored) to decode or decrypt.");
            Console.WriteLine("-p, --purpose Purpose of the encrypteddata");
            Console.WriteLine("-a, --valalgo Validation algorithm.");
            Console.WriteLine("-b, --decalgo Decryption algorithm.");
            Console.WriteLine("-i, --IISDirPath Application dir path in IIS tree.");
            Console.WriteLine("-t, --TargetPagePath Target page path");
            Console.WriteLine("-v, --antiCSRFToken Anti CSRF Token value");
        }
    }
}
