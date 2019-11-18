using CommandLine;
using System;
using System.IO;

namespace NotSoSecure.AspDotNetWrapper
{
    class AspDotNetWrapper
    {
        public static string strDecryptedTxtFilePath = AppDomain.CurrentDomain.BaseDirectory + "DecryptedText.txt";

        static void Main(string[] args)
        {
            string strKeysFilePath = null,
                strEncryptedData = null,
                strDecryptDataFilePath = null,
                strPurpose = null,
                strModifier = null,
                strIISAppPath = null,
                strTargetPagePath = null,
                strAntiCSRFToken = null;
            bool bDecrypt = false, bDecode = false;
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(options =>
                {
                    strKeysFilePath = options.strKeysFilePath;
                    strEncryptedData = options.strEncryptedData;
                    strPurpose = options.strPurpose;
                    strDecryptDataFilePath = options.strDecryptDataFilePath;
                    strModifier = options.strModifier;
                    strIISAppPath = options.strIISDirPath;
                    strTargetPagePath = options.strTargetPagePath;
                    strAntiCSRFToken = options.strAntiCSRFToken;
                    bDecrypt = options.bDecrypt;
                    bDecode = options.bDecode;
                    if (!String.IsNullOrEmpty(options.strOutputFilePath))
                        strDecryptedTxtFilePath = options.strOutputFilePath;
                });
            if (strPurpose != null)
                DefinePurpose.SetPurposeString(strPurpose);
            else
            {
                if (bDecrypt)
                {
                    Options.GetUsage(true);
                    return;
                }
            }
            if (DefinePurpose.enumPurpose == EnumPurpose.VIEWSTATE && bDecode)
            {
                if (strKeysFilePath == null || strEncryptedData == null || strPurpose == null || strModifier == null)
                {
                    Options.GetViewStateLegacyUsage();
                }
                else
                {
                    if (File.Exists(strKeysFilePath))
                    {
                        byte[] protectedData = DefinePurpose.GetProtectedData(ReadDataFromFile(strEncryptedData));
                        if (protectedData != null)
                        {
                            EncryptDecrypt.DecodeViewState(protectedData, strKeysFilePath, strModifier, strPurpose);
                        }
                    }
                }

            }
            else
            {
                if (bDecrypt)
                {
                    if (DefinePurpose.enumPurpose == EnumPurpose.VIEWSTATE)
                    {
                        if (strKeysFilePath == null || strEncryptedData == null || strPurpose == null || strIISAppPath == null || strTargetPagePath == null )
                        {
                            Options.GetViewStateUsage();
                            return;
                        }
                    }
                    else
                    {
                        if (strKeysFilePath == null || strEncryptedData == null || strPurpose == null)
                        {
                            Options.GetUsage(true);
                            return;
                        }
                    }
                    if (File.Exists(strKeysFilePath))
                    {
                        byte[] protectedData = DefinePurpose.GetProtectedData(ReadDataFromFile(strEncryptedData));
                        if (protectedData != null)
                        {
                            
                            byte[] clearData = EncryptDecrypt.DecryptData(protectedData, strKeysFilePath, strTargetPagePath, strIISAppPath, strAntiCSRFToken);
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
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Write("\n\nKey path file {0} not found!!\n", strKeysFilePath);
                        Console.ResetColor();
                    }
                }
                else
                {
                    if (strDecryptDataFilePath == null)
                    {
                        Options.GetUsage(false);
                    }
                    else
                    {
                        if (File.Exists(strDecryptDataFilePath))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\nEncryptedData");
                            Console.WriteLine("-------------");
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(EncryptDecrypt.EncryptData(strDecryptDataFilePath));
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.Write("\n\nDecryptedText.txt File not found!!\n");
                            Console.ResetColor();
                        }
                    }
                }
            }
        }

        private static string ReadDataFromFile(string strPath)
        {
            string strData = String.Empty;
            if(File.Exists(strPath))
            {
                strData = File.ReadAllText(strPath);
            }
            else
            {
                strData = strPath;
            }
            return strData;
        }
    }
}