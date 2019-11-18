using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security.Cryptography;

namespace NotSoSecure.AspDotNetWrapper
{
    enum EnumPurpose
    {
        OWINCOOKIE,
        ASPXAUTH,
        SCRIPTRESOURCE,
        WEBRESOURCE,
        VIEWSTATE,
        UNKNOWN
    }

    class DefinePurpose
    {
        public static EnumPurpose enumPurpose = EnumPurpose.UNKNOWN;
        public static void SetPurposeString(string strPurpose)
        {
            switch (strPurpose.ToLower())
            {
                case "owin.cookie":
                    enumPurpose = EnumPurpose.OWINCOOKIE;
                    break;
                case "aspxauth":
                    enumPurpose = EnumPurpose.ASPXAUTH;
                    break;
                case "viewstate":
                    enumPurpose = EnumPurpose.VIEWSTATE;
                    break;
                case "scriptresource":
                    enumPurpose = EnumPurpose.SCRIPTRESOURCE;
                    break;
                case "webresource":
                    enumPurpose = EnumPurpose.WEBRESOURCE;
                    break;
                default:
                    enumPurpose = EnumPurpose.UNKNOWN;
                    break;
            }
        }

        public static byte [] GetProtectedData(string strEncryptedText)
        {
            byte[] byteProtectedData = null;
            switch (enumPurpose)
            {
                case EnumPurpose.OWINCOOKIE:
                    strEncryptedText = strEncryptedText.Replace('-', '+').Replace('_', '/');
                    var padding = 3 - ((strEncryptedText.Length + 3) % 4);
                    if (padding != 0)
                        strEncryptedText = strEncryptedText + new string('=', padding);
                    byteProtectedData = Convert.FromBase64String(strEncryptedText);
                    break;
                case EnumPurpose.ASPXAUTH:
                    byteProtectedData = CryptoUtil.HexToBinary(strEncryptedText);
                    break;
                case EnumPurpose.WEBRESOURCE:
                    byteProtectedData = HttpServerUtility.UrlTokenDecode(strEncryptedText);
                    break;
                case EnumPurpose.SCRIPTRESOURCE:
                    byteProtectedData = HttpServerUtility.UrlTokenDecode(strEncryptedText);
                    break;
                case EnumPurpose.VIEWSTATE:
                    byteProtectedData = System.Convert.FromBase64String(strEncryptedText);
                    break;
                case EnumPurpose.UNKNOWN:
                    byteProtectedData = null;
                    break;
                default:
                    byteProtectedData = null;
                    break;
            }
            return byteProtectedData;
        }

        public static Purpose GetPurpose()
        {
            Purpose objPurpose = null;
            switch (enumPurpose)
            {
                case EnumPurpose.OWINCOOKIE:
                    Dictionary<string, Purpose> dictPurposeMap = new Dictionary<string, Purpose>(StringComparer.Ordinal)
                    {
                        { "owin.cookie", Purpose.User_MachineKey_Protect.AppendSpecificPurposes(
                            new [] {
                                "Microsoft.Owin.Security.Cookies.CookieAuthenticationMiddleware",
                                "ApplicationCookie",
                                "v1"
                                }
                            )
                        }
                    };
                    dictPurposeMap.TryGetValue("owin.cookie", out objPurpose);
                    break;
                case EnumPurpose.ASPXAUTH:
                    objPurpose = new Purpose("FormsAuthentication.Ticket");
                    break;
                case EnumPurpose.WEBRESOURCE:
                    objPurpose = new Purpose("AssemblyResourceLoader.WebResourceUrl");
                    break;
                case EnumPurpose.SCRIPTRESOURCE:
                    objPurpose = new Purpose("ScriptResourceHandler.ScriptResourceUrl");
                    break;
                case EnumPurpose.VIEWSTATE:
                    //Written separate function
                    objPurpose = null;
                    break;
                case EnumPurpose.UNKNOWN:
                    objPurpose = null;
                    break;
                default:
                    objPurpose = null;
                    break;
            }
            return objPurpose;
        }

        public static void GetPurposeAndClearData(ReadObject objData, out Purpose objPurpose, out byte[] byteClearData)
        {
            switch (enumPurpose)
            {
                case EnumPurpose.OWINCOOKIE:
                    Dictionary<string, Purpose> dictPurposeMap = new Dictionary<string, Purpose>(StringComparer.Ordinal)
                    {
                        { "owin.cookie", Purpose.User_MachineKey_Protect.AppendSpecificPurposes(
                            new [] {
                                "Microsoft.Owin.Security.Cookies.CookieAuthenticationMiddleware",
                                "ApplicationCookie",
                                "v1"
                                }
                            )
                        }
                    };
                    dictPurposeMap.TryGetValue("owin.cookie", out objPurpose);
                    byteClearData = DataWriter.Compress(StringToHexByteArray(objData.AspNetAppCookie));
                    break;
                case EnumPurpose.ASPXAUTH:
                    objPurpose = Purpose.FormsAuthentication_Ticket;
                    byteClearData = FormAuthenticationHelper.ConvertToBytes(objData.objFormAuthCookie);
                    break;
                case EnumPurpose.WEBRESOURCE:
                    objPurpose = Purpose.AssemblyResourceLoader_WebResourceUrl;
                    byteClearData = Encoding.ASCII.GetBytes(objData.WebResourceData);
                    break;
                case EnumPurpose.SCRIPTRESOURCE:
                    objPurpose = Purpose.ScriptResourceHandler_ScriptResourceUrl;
                    byteClearData = Encoding.ASCII.GetBytes(objData.ScriptResourceData);
                    break;
                case EnumPurpose.VIEWSTATE:
                    byteClearData = null;
                    objPurpose = null;
                    break;
                case EnumPurpose.UNKNOWN:
                    byteClearData = null;
                    objPurpose = null;
                    break;
                default:
                    byteClearData = null;
                    objPurpose = null;
                    break;
            }
        }

        private static byte[] StringToHexByteArray(string strHexString)
        {
            byte[] byteOutArray = new byte[strHexString.Length];
            int nIndex = 0;
            foreach (char cTmp in strHexString)
            {
                byteOutArray[nIndex++] = Convert.ToByte(cTmp);
            }
            return byteOutArray;
        }

        public static Purpose GetViewStatePurpose(string targetPagePath, string IISAppInPath, string viewStateUserKey)
        {
            Purpose objPurpose = Purpose.WebForms_HiddenFieldPageStatePersister_ClientState;
            string newTargetPagePath = simulateTemplateSourceDirectory(targetPagePath);
            newTargetPagePath = newTargetPagePath == null ? "/" : newTargetPagePath;
            List<string> specificPurposes = new List<string>() {
                "TemplateSourceDirectory: " + newTargetPagePath.ToUpperInvariant(),
                "Type: " + simulateGetTypeName(targetPagePath, IISAppInPath).ToUpperInvariant()
            };
            if (!string.IsNullOrEmpty(viewStateUserKey))
            {
                specificPurposes.Add("ViewStateUserKey: " + viewStateUserKey);
            }
            return objPurpose.AppendSpecificPurposes(specificPurposes);
        }
        #region Third party function
        //Entire regions function copied from following source
        //https://github.com/pwntester/ysoserial.net/blob/master/ysoserial/Plugins/ViewStatePlugin.cs
        private static String simulateTemplateSourceDirectory(String strPath)
        {

            if (!strPath.StartsWith("/"))
                strPath = "/" + strPath;

            String result = strPath;

            if (result.LastIndexOf(".") > result.LastIndexOf("/"))
            {
                // file name needs to be removed
                result = result.Substring(0, result.LastIndexOf("/"));
            }
            result = RemoveSlashFromPathIfNeeded(result);

            return result;
        }

        private static String simulateGetTypeName(String strPath, String IISAppInPath)
        {

            if (!strPath.StartsWith("/"))
                strPath = "/" + strPath;

            String result = strPath;

            if (!result.ToLower().EndsWith(".aspx"))
                result += "/default.aspx";

            IISAppInPath = IISAppInPath.ToLower();
            if (!IISAppInPath.StartsWith("/"))
                IISAppInPath = "/" + IISAppInPath;
            if (!IISAppInPath.EndsWith("/"))
                IISAppInPath += "/";

            if (result.ToLower().IndexOf(IISAppInPath) >= 0)
                result = result.Substring(result.ToLower().IndexOf(IISAppInPath) + IISAppInPath.Length);

            // to get rid of the first /
            if (result.StartsWith("/"))
                result = result.Substring(1);

            result = result.Replace(".", "_").Replace("/", "_");

            result = RemoveSlashFromPathIfNeeded(result);

            return result;
        }

        private static string CanonThePath(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return null;
            }
            Regex regexBackSlash = new Regex("\\\\");
            Regex regexDoubleSlash = new Regex("[/]+");
            path = regexBackSlash.Replace(path, "/");
            path = regexDoubleSlash.Replace(path, "/");
            return path;
        }

        private static string RemoveSlashFromPathIfNeeded(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return null;
            }
            int l = path.Length;
            if (l <= 1 || path[l - 1] != '/')
            {
                return path;
            }

            return path.Substring(0, l - 1);
        }
        #endregion  Third party function
    }
}
