using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Security;
using System.Web.Security.Cryptography;

namespace NotSoSecure.AspDotNetWrapper
{
    //Copied from https://github.com/synercoder/FormsAuthentication/blob/master/src/Synercoding.FormsAuthentication/FormsAuthenticationCryptor.cs
    class FormAuthenticationHelper
    {
        public static FormsAuthenticationCookie ConvertToAuthenticationTicket(byte[] byteClearData)
        {
            using (SerializingBinaryReader ticketReader = new SerializingBinaryReader(new MemoryStream(byteClearData)))
            {
                byte serializedFormatVersion = ticketReader.ReadByte();
                if (serializedFormatVersion != 0x01)
                    throw new ArgumentException("The data is not in the correct format, first byte must be 0x01.", nameof(byteClearData));

                int ticketVersion = ticketReader.ReadByte();

                DateTime ticketIssueDateUtc = new DateTime(ticketReader.ReadInt64(), DateTimeKind.Utc);

                byte spacer = ticketReader.ReadByte();
                if (spacer != 0xFE)
                    throw new ArgumentException("The data is not in the correct format, tenth byte must be 0xFE.", nameof(byteClearData));

                DateTime ticketExpirationDateUtc = new DateTime(ticketReader.ReadInt64(), DateTimeKind.Utc);
                bool ticketIsPersistent = ticketReader.ReadByte() == 1;

                string ticketName = ticketReader.ReadBinaryString();
                string ticketUserData = ticketReader.ReadBinaryString();
                string ticketCookiePath = ticketReader.ReadBinaryString();
                byte footer = ticketReader.ReadByte();
                if (footer != 0xFF)
                    throw new ArgumentException("The data is not in the correct format, footer byte must be 0xFF.", nameof(byteClearData));

                //create ticket
                return new FormsAuthenticationCookie()
                {
                    UserName = ticketName,
                    UserData = ticketUserData,
                    CookiePath = ticketCookiePath,
                    IsPersistent = ticketIsPersistent,
                    IssuedUtc = ticketIssueDateUtc,
                    ExpiresUtc = ticketExpirationDateUtc
                };
            }
        }

        public static byte[] ConvertToBytes(FormsAuthenticationCookie data)
        {
            using (var ticketBlobStream = new MemoryStream())
            using (var ticketWriter = new SerializingBinaryWriter(ticketBlobStream))
            {
                ticketWriter.Write((byte)1);
                ticketWriter.Write((byte)1);
                ticketWriter.Write(data.IssuedUtc.Ticks);
                ticketWriter.Write((byte)0xfe);
                ticketWriter.Write(data.ExpiresUtc.Ticks);
                ticketWriter.Write(data.IsPersistent);
                ticketWriter.WriteBinaryString(data.UserName ?? "");
                ticketWriter.WriteBinaryString(data.UserData ?? "");
                ticketWriter.WriteBinaryString(data.CookiePath ?? "");
                ticketWriter.Write((byte)0xff);

                return ticketBlobStream.ToArray();
            }
        }
    }
}
