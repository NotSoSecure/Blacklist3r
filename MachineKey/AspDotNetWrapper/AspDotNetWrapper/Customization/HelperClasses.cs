using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NotSoSecure.AspDotNetWrapper
{
    public enum EncryptionMethod
    {
        AES,
        TripleDES
    }

    public class FormsAuthenticationCookie
    {
        public DateTime IssuedUtc { get; set; }
        public DateTime ExpiresUtc { get; set; }
        public bool IsPersistent { get; set; }
        public string UserName { get; set; }
        public string UserData { get; set; }
        public string CookiePath { get; set; }
    }

    public enum ValidationMethod
    {
        SHA1,
        HMACSHA256,
        HMACSHA384,
        HMACSHA512
    }

    public class FormsAuthenticationOptions
    {
        public EncryptionMethod EncryptionMethod { get; set; } = EncryptionMethod.AES;
        public ValidationMethod ValidationMethod { get; set; } = ValidationMethod.HMACSHA256;

        public string DecryptionKey { get; set; }
        public string ValidationKey { get; set; }
    }

    class ContantValue
    {
        public static string strDecryptionKey = "DecryptionKey:";
        public static string strDecryptionAlgo = "DecryptionAlgo:";
        public static string strValidationKey = "ValidationKey:";
        public static string strValidationAlgo = "ValidationAlgo:";
        public static string strPurpose = "Purpose:";
        public static string strEncryptionIV = "EncryptionIV:";
        public static string strAspNetApplicationCookie = ".AspNet.ApplicationCookie:";
        public static string strWebResourceData = "WebResourceData:";
        public static string strScriptResourceData = "ScriptResourceData:";
        public static string strIssuedUTC = "IssuedUTC:";
        public static string strExpireUTC = "ExpiredUTC:";
        public static string strIsPersistent = "IsPersistent:";
        public static string strUserName = "UserName:";
        public static string strUserData = "UserData:";
        public static string strCookiePath = "CookiePath:";

        public static string[] arrayDecryptionAlgo = { "AES", "DES", "TripleDES" };
        public static string[] arrayValidationAlgo = { "SHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512" };
    }

    class ReadObject
    {
        public string DecryptionKey { get; set; }
        public string DecryptionAlgo { get; set; }
        public string ValidationKey { get; set; }
        public string ValidationAlgo { get; set; }
        public byte [] EncryptionIV { get; set; }
        public string Purpose { get; set; }
        public string AspNetAppCookie { get; set; }
        public string WebResourceData { get; set; }
        public string ScriptResourceData { get; set; }
        public bool IsError { get; set; }
        public FormsAuthenticationCookie objFormAuthCookie = new FormsAuthenticationCookie();

        public ReadObject(string strDecryptDataFilePath)
        {
            IsError = false;
            StreamReader streamReader = new System.IO.StreamReader(strDecryptDataFilePath);
            string line = string.Empty;
            while ((line = streamReader.ReadLine()) != null)
            {
                if (line.Contains(ContantValue.strDecryptionKey))
                {
                    DecryptionKey = line.Substring(ContantValue.strDecryptionKey.Length);
                }
                else if (line.Contains(ContantValue.strDecryptionAlgo))
                {
                    DecryptionAlgo = line.Substring(ContantValue.strDecryptionAlgo.Length);
                }
                else if (line.Contains(ContantValue.strValidationKey))
                {
                    ValidationKey = line.Substring(ContantValue.strValidationKey.Length);
                }
                else if (line.Contains(ContantValue.strValidationAlgo))
                {
                    ValidationAlgo = line.Substring(ContantValue.strValidationAlgo.Length);
                }
                else if (line.Contains(ContantValue.strEncryptionIV))
                {
                    EncryptionIV = Convert.FromBase64String(line.Substring(ContantValue.strEncryptionIV.Length));
                }
                else if (line.Contains(ContantValue.strPurpose))
                {
                    Purpose = line.Substring(ContantValue.strPurpose.Length);
                }
                else if (line.Contains(ContantValue.strAspNetApplicationCookie))
                {
                    AspNetAppCookie = line.Substring(ContantValue.strAspNetApplicationCookie.Length);
                }
                else if (line.Contains(ContantValue.strIssuedUTC))
                {
                    objFormAuthCookie.IssuedUtc = DateTime.Parse(line.Substring(ContantValue.strIssuedUTC.Length));
                }
                else if (line.Contains(ContantValue.strExpireUTC))
                {
                    objFormAuthCookie.ExpiresUtc = DateTime.Parse(line.Substring(ContantValue.strExpireUTC.Length));
                }
                else if (line.Contains(ContantValue.strIsPersistent))
                {
                    objFormAuthCookie.IsPersistent = bool.Parse(line.Substring(ContantValue.strIsPersistent.Length));
                }
                else if (line.Contains(ContantValue.strCookiePath))
                {
                    objFormAuthCookie.CookiePath = line.Substring(ContantValue.strCookiePath.Length);
                }
                else if (line.Contains(ContantValue.strUserData))
                {
                    objFormAuthCookie.UserData = line.Substring(ContantValue.strUserData.Length);
                }
                else if (line.Contains(ContantValue.strUserName))
                {
                    objFormAuthCookie.UserName = line.Substring(ContantValue.strUserName.Length);
                }
                else if (line.Contains(ContantValue.strWebResourceData))
                {
                    WebResourceData = line.Substring(ContantValue.strWebResourceData.Length);
                }
                else if (line.Contains(ContantValue.strScriptResourceData))
                {
                    ScriptResourceData = line.Substring(ContantValue.strScriptResourceData.Length);
                }
                else
                {
                    IsError = true;
                }
            }
            streamReader.Close();
        }
    }
}
