using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Web;
using System.Web.Security.Cryptography;
using System.Web.Configuration;
using System.Reflection;
using System.Web.UI;
using System.IO;

namespace NotSoSecure.AspDotNetWrapper
{
    class AspDotNetWrapper
    {
        public static string strDecryptedTxtFilePath = AppDomain.CurrentDomain.BaseDirectory + "DecryptedText.txt";

        static void Main(string[] args)
        {
            string strKeysFilePath = null, strCookieValue = null, strDecryptDataFilePath = null, strPurpose = null, strValidationAlgorithm = null, strDecryptionAlgorithm = null;
            bool bDecrypt = false;
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(options =>
                {
                    strKeysFilePath = options.strKeysFilePath;
                    strCookieValue = options.strCookieValue;
                    strValidationAlgorithm = options.strValidationAlgorithm;
                    strDecryptionAlgorithm = options.strDecryptionAlgorithm;
                    strPurpose = options.strPurpose;
                    strDecryptDataFilePath = options.strDecryptDataFilePath;
                    bDecrypt = options.bDecrypt;
                });

            if (strValidationAlgorithm != null)
                strValidationAlgorithm = strValidationAlgorithm.ToUpper();
            if (strDecryptionAlgorithm != null)
                strDecryptionAlgorithm = strDecryptionAlgorithm.ToUpper();
            if (strPurpose != null)
                DefinePurpose.SetPurposeString(strPurpose);

            if (bDecrypt)
            {
                if (strKeysFilePath == null || strCookieValue == null || strValidationAlgorithm == null
                    || strDecryptionAlgorithm == null || strPurpose == null )
                {
                    Options.GetUsage(true);
                }
                else
                {
                    byte[] protectedData = DefinePurpose.GetProtectedData(strCookieValue);
                    if (protectedData != null)
                    {
                        byte[] clearData = EncryptDecrypt.DecryptData(protectedData, strKeysFilePath, strValidationAlgorithm, strDecryptionAlgorithm);
                        if (clearData != null)
                        {
                            DataWriter.WritePurposeToFile(strPurpose);
                            DataWriter.WriteOtherDataToFile(DefinePurpose.enumPurpose, clearData);
                        }
                    }
                    else
                    {
                        Console.Write("Failed to get protected data!!");
                    }
                }
            }
            else
            {
                if (strDecryptedTxtFilePath == null)
                {
                    Options.GetUsage(false);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\nEncryptedData");
                    Console.WriteLine("-------------");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(EncryptDecrypt.EncryptData());
                    Console.ResetColor();
                }
            }
        }
    }
}