using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
                    byteProtectedData = null;
                    break;
                case EnumPurpose.VIEWSTATE:
                    byteProtectedData = null;
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
                    objPurpose = null;
                    break;
                case EnumPurpose.VIEWSTATE:
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
                    byteClearData = null;
                    break;
                case EnumPurpose.SCRIPTRESOURCE:
                    byteClearData = null;
                    objPurpose = null;
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
    }
}
