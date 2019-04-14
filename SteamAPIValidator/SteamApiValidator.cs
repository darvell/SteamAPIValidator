/*
 *  Copyright (c) 2018 Darvell Long

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
 *
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Messaging;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SteamAPIValidator
{
    #region WinCrypt

    internal static class WinCrypt
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            public String pszObjId;
            private BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_ID
        {
            public int dwIdChoice;
            public BLOB IssuerSerialNumberOrKeyIdOrHashId;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct SIGNER_SUBJECT_INFO
        {
            /// DWORD->unsigned int
            public uint cbSize;

            /// DWORD*
            public System.IntPtr pdwIndex;

            /// DWORD->unsigned int
            public uint dwSubjectChoice;

            /// SubjectChoiceUnion
            public SubjectChoiceUnion Union1;
        }

        [StructLayoutAttribute(LayoutKind.Explicit)]
        public struct SubjectChoiceUnion
        {
            /// SIGNER_FILE_INFO*
            [FieldOffsetAttribute(0)]
            public System.IntPtr pSignerFileInfo;

            /// SIGNER_BLOB_INFO*
            [FieldOffsetAttribute(0)]
            public System.IntPtr pSignerBlobInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_NAME_BLOB
        {
            public uint cbData;

            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)]
            public byte[] pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_INTEGER_BLOB
        {
            public UInt32 cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ATTR_BLOB
        {
            public uint cbData;

            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)]
            public byte[] pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ATTRIBUTE
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszObjId;

            public uint cValue;

            [MarshalAs(UnmanagedType.LPStruct)]
            public CRYPT_ATTR_BLOB rgValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CMSG_SIGNER_INFO
        {
            public int dwVersion;
            private CERT_NAME_BLOB Issuer;
            private CRYPT_INTEGER_BLOB SerialNumber;
            private CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
            private CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
            private BLOB EncryptedHash;
            private CRYPT_ATTRIBUTE[] AuthAttrs;
            private CRYPT_ATTRIBUTE[] UnauthAttrs;
        }

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptQueryObject(
            int dwObjectType,
            IntPtr pvObject,
            int dwExpectedContentTypeFlags,
            int dwExpectedFormatTypeFlags,
            int dwFlags,
            out int pdwMsgAndCertEncodingType,
            out int pdwContentType,
            out int pdwFormatType,
            ref IntPtr phCertStore,
            ref IntPtr phMsg,
            ref IntPtr ppvContext);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptMsgGetParam(
            IntPtr hCryptMsg,
            int dwParamType,
            int dwIndex,
            IntPtr pvData,
            ref int pcbData
        );

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptMsgGetParam(
            IntPtr hCryptMsg,
            int dwParamType,
            int dwIndex,
            [In, Out] byte[] vData,
            ref int pcbData
        );

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptDecodeObject(
          uint CertEncodingType,
          UIntPtr lpszStructType,
          byte[] pbEncoded,
          uint cbEncoded,
          uint flags,
          [In, Out] byte[] pvStructInfo,
          ref uint cbStructInfo);

        public const int CRYPT_ASN_ENCODING = 0x00000001;
        public const int CRYPT_NDR_ENCODING = 0x00000002;
        public const int X509_ASN_ENCODING = 0x00000001;
        public const int X509_NDR_ENCODING = 0x00000002;
        public const int PKCS_7_ASN_ENCODING = 0x00010000;
        public const int PKCS_7_NDR_ENCODING = 0x00020000;

        public static UIntPtr PKCS7_SIGNER_INFO = new UIntPtr(500);
        public static UIntPtr CMS_SIGNER_INFO = new UIntPtr(501);

        public static string szOID_RSA_signingTime = "1.2.840.113549.1.9.5";
        public static string szOID_RSA_counterSign = "1.2.840.113549.1.9.6";

        //+-------------------------------------------------------------------------
        //  Get parameter types and their corresponding data structure definitions.
        //--------------------------------------------------------------------------
        public const int CMSG_TYPE_PARAM = 1;

        public const int CMSG_CONTENT_PARAM = 2;
        public const int CMSG_BARE_CONTENT_PARAM = 3;
        public const int CMSG_INNER_CONTENT_TYPE_PARAM = 4;
        public const int CMSG_SIGNER_COUNT_PARAM = 5;
        public const int CMSG_SIGNER_INFO_PARAM = 6;
        public const int CMSG_SIGNER_CERT_INFO_PARAM = 7;
        public const int CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8;
        public const int CMSG_SIGNER_AUTH_ATTR_PARAM = 9;
        public const int CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10;
        public const int CMSG_CERT_COUNT_PARAM = 11;
        public const int CMSG_CERT_PARAM = 12;
        public const int CMSG_CRL_COUNT_PARAM = 13;
        public const int CMSG_CRL_PARAM = 14;
        public const int CMSG_ENVELOPE_ALGORITHM_PARAM = 15;
        public const int CMSG_RECIPIENT_COUNT_PARAM = 17;
        public const int CMSG_RECIPIENT_INDEX_PARAM = 18;
        public const int CMSG_RECIPIENT_INFO_PARAM = 19;
        public const int CMSG_HASH_ALGORITHM_PARAM = 20;
        public const int CMSG_HASH_DATA_PARAM = 21;
        public const int CMSG_COMPUTED_HASH_PARAM = 22;
        public const int CMSG_ENCRYPT_PARAM = 26;
        public const int CMSG_ENCRYPTED_DIGEST = 27;
        public const int CMSG_ENCODED_SIGNER = 28;
        public const int CMSG_ENCODED_MESSAGE = 29;
        public const int CMSG_VERSION_PARAM = 30;
        public const int CMSG_ATTR_CERT_COUNT_PARAM = 31;
        public const int CMSG_ATTR_CERT_PARAM = 32;
        public const int CMSG_CMS_RECIPIENT_COUNT_PARAM = 33;
        public const int CMSG_CMS_RECIPIENT_INDEX_PARAM = 34;
        public const int CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35;
        public const int CMSG_CMS_RECIPIENT_INFO_PARAM = 36;
        public const int CMSG_UNPROTECTED_ATTR_PARAM = 37;
        public const int CMSG_SIGNER_CERT_ID_PARAM = 38;
        public const int CMSG_CMS_SIGNER_INFO_PARAM = 39;

        //-------------------------------------------------------------------------
        //dwObjectType for CryptQueryObject
        //-------------------------------------------------------------------------
        public const int CERT_QUERY_OBJECT_FILE = 0x00000001;

        public const int CERT_QUERY_OBJECT_BLOB = 0x00000002;

        //-------------------------------------------------------------------------
        //dwContentType for CryptQueryObject
        //-------------------------------------------------------------------------
        //encoded single certificate
        public const int CERT_QUERY_CONTENT_CERT = 1;

        //encoded single CTL
        public const int CERT_QUERY_CONTENT_CTL = 2;

        //encoded single CRL
        public const int CERT_QUERY_CONTENT_CRL = 3;

        //serialized store
        public const int CERT_QUERY_CONTENT_SERIALIZED_STORE = 4;

        //serialized single certificate
        public const int CERT_QUERY_CONTENT_SERIALIZED_CERT = 5;

        //serialized single CTL
        public const int CERT_QUERY_CONTENT_SERIALIZED_CTL = 6;

        //serialized single CRL
        public const int CERT_QUERY_CONTENT_SERIALIZED_CRL = 7;

        //a PKCS#7 signed message
        public const int CERT_QUERY_CONTENT_PKCS7_SIGNED = 8;

        //a PKCS#7 message, such as enveloped message.  But it is not a signed message,
        public const int CERT_QUERY_CONTENT_PKCS7_UNSIGNED = 9;

        //a PKCS7 signed message embedded in a file
        public const int CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10;

        //an encoded PKCS#10
        public const int CERT_QUERY_CONTENT_PKCS10 = 11;

        //an encoded PKX BLOB
        public const int CERT_QUERY_CONTENT_PFX = 12;

        //an encoded CertificatePair (contains forward and/or reverse cross certs)
        public const int CERT_QUERY_CONTENT_CERT_PAIR = 13;

        //-------------------------------------------------------------------------
        //dwExpectedConentTypeFlags for CryptQueryObject
        //-------------------------------------------------------------------------
        //encoded single certificate
        public const int CERT_QUERY_CONTENT_FLAG_CERT = (1 << CERT_QUERY_CONTENT_CERT);

        //encoded single CTL
        public const int CERT_QUERY_CONTENT_FLAG_CTL = (1 << CERT_QUERY_CONTENT_CTL);

        //encoded single CRL
        public const int CERT_QUERY_CONTENT_FLAG_CRL = (1 << CERT_QUERY_CONTENT_CRL);

        //serialized store
        public const int CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE = (1 << CERT_QUERY_CONTENT_SERIALIZED_STORE);

        //serialized single certificate
        public const int CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT = (1 << CERT_QUERY_CONTENT_SERIALIZED_CERT);

        //serialized single CTL
        public const int CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL = (1 << CERT_QUERY_CONTENT_SERIALIZED_CTL);

        //serialized single CRL
        public const int CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL = (1 << CERT_QUERY_CONTENT_SERIALIZED_CRL);

        //an encoded PKCS#7 signed message
        public const int CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = (1 << CERT_QUERY_CONTENT_PKCS7_SIGNED);

        //an encoded PKCS#7 message.  But it is not a signed message
        public const int CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = (1 << CERT_QUERY_CONTENT_PKCS7_UNSIGNED);

        //the content includes an embedded PKCS7 signed message
        public const int CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = (1 << CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED);

        //an encoded PKCS#10
        public const int CERT_QUERY_CONTENT_FLAG_PKCS10 = (1 << CERT_QUERY_CONTENT_PKCS10);

        //an encoded PFX BLOB
        public const int CERT_QUERY_CONTENT_FLAG_PFX = (1 << CERT_QUERY_CONTENT_PFX);

        //an encoded CertificatePair (contains forward and/or reverse cross certs)
        public const int CERT_QUERY_CONTENT_FLAG_CERT_PAIR = (1 << CERT_QUERY_CONTENT_CERT_PAIR);

        //content can be any type
        public const int CERT_QUERY_CONTENT_FLAG_ALL =
            CERT_QUERY_CONTENT_FLAG_CERT |
            CERT_QUERY_CONTENT_FLAG_CTL |
            CERT_QUERY_CONTENT_FLAG_CRL |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED |
            CERT_QUERY_CONTENT_FLAG_PKCS10 |
            CERT_QUERY_CONTENT_FLAG_PFX |
            CERT_QUERY_CONTENT_FLAG_CERT_PAIR;

        //-------------------------------------------------------------------------
        //dwFormatType for CryptQueryObject
        //-------------------------------------------------------------------------
        //the content is in binary format
        public const int CERT_QUERY_FORMAT_BINARY = 1;

        //the content is base64 encoded
        public const int CERT_QUERY_FORMAT_BASE64_ENCODED = 2;

        //the content is ascii hex encoded with "{ASN}" prefix
        public const int CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3;

        //-------------------------------------------------------------------------
        //dwExpectedFormatTypeFlags for CryptQueryObject
        //-------------------------------------------------------------------------
        //the content is in binary format
        public const int CERT_QUERY_FORMAT_FLAG_BINARY = (1 << CERT_QUERY_FORMAT_BINARY);

        //the content is base64 encoded
        public const int CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = (1 << CERT_QUERY_FORMAT_BASE64_ENCODED);

        //the content is ascii hex encoded with "{ASN}" prefix
        public const int CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = (1 << CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED);

        //the content can be of any format
        public const int CERT_QUERY_FORMAT_FLAG_ALL =
            CERT_QUERY_FORMAT_FLAG_BINARY |
            CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED |
            CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED;
    }

    #endregion WinCrypt

    public static class SteamApiValidator
    {
        #region P/Invoke Methods

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [PreserveSig]
        private static extern uint GetModuleFileName
        (
            [In] IntPtr hModule,
            [Out] StringBuilder lpFilename,
            [In][MarshalAs(UnmanagedType.U4)] int nSize
        );

        #endregion P/Invoke Methods

        private const int MAX_PATH_SIZE = 32767; // Windows <10 are 256, GPO's now allow max paths of 32767

        /// <summary>
        /// Determines whether a valid steam API DLL has been loaded and is codesigned by Valve.
        /// </summary>
        /// <returns><c>true</c> if steam API DLL has a valid Valve signature otherwise, <c>false</c>.</returns>
        public static bool IsValidSteamApiDll()
        {
            foreach (string steamDllName in new[] { "steam_api64.dll", "steam_api.dll" })
            {
                IntPtr steamApiPtr = GetModuleHandle(steamDllName);

                if (steamApiPtr == IntPtr.Zero)
                {
                    Debug.WriteLine("Steam API has not loaded. Forcing an emergency load, this won't cause issues.");
                    steamApiPtr = LoadLibrary(steamDllName);
                }
                if (steamApiPtr == IntPtr.Zero)
                {
                    Debug.WriteLine("Steam API not found.");
                    return false;
                }

                if (steamApiPtr != IntPtr.Zero)
                {
                    StringBuilder fileBuilder = new StringBuilder(MAX_PATH_SIZE);
                    if (GetModuleFileName(steamApiPtr, fileBuilder, MAX_PATH_SIZE) > 0) // 0 means you screwed up.
                    {
                        return CheckIfValveSigned(fileBuilder.ToString());
                    }
                }
            }

            return false;
        }

        public static bool IsSteamClientUsed()
        {
            return Directory.GetFileSystemEntries(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                       "steamclien*.dll", SearchOption.AllDirectories).Length > 0;
        }

        /// <summary>
        /// Determines whether the loaded Steam client library is codesigned by Valve. Not all games use this.
        /// </summary>
        /// <returns><c>true</c> if steamclient is codesigned; otherwise, <c>false</c>.</returns>
        public static bool IsValidSteamClientDll()
        {
            string steamClientDllName = Environment.Is64BitProcess ? "steamclient64.dll" : "steamclient.dll";
            IntPtr steamClientPtr = GetModuleHandle(steamClientDllName);

            if (steamClientPtr == IntPtr.Zero)
            {
                bool deepCheck = false;
                bool anySteamClient = false;
                foreach (var steamDlls in Directory.GetFileSystemEntries(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                    "steamclien*.dll", SearchOption.AllDirectories))
                {
                    anySteamClient = true;
                    if (!CheckIfValveSigned(steamDlls))
                    {
                        try
                        {
                            Console.WriteLine($"Invalid DLL found. {steamDlls}");
                            new FileInfo(steamDlls).MoveTo("PEOPLE_WORKED_HARD.CMON");
                        }
                        catch
                        {
                            Console.WriteLine("Couldn't remove offending Steam DLL.");
                        }
                    }
                    else
                    {
                        deepCheck = true;
                    }
                }

                return deepCheck;
            }

            if (steamClientPtr != IntPtr.Zero)
            {
                StringBuilder fileBuilder = new StringBuilder(MAX_PATH_SIZE);
                if (GetModuleFileName(steamClientPtr, fileBuilder, MAX_PATH_SIZE) > 0) // 0 means you screwed up.
                {
                    return CheckIfValveSigned(fileBuilder.ToString());
                }
            }

            return false;
        }

        private static X509Certificate2 GetDigitalCertificate(string filePath)
        {
            X509Certificate2 cert = null;

            int encodingType;
            int contentType;
            int formatType;
            IntPtr certStore = IntPtr.Zero;
            IntPtr cryptMsg = IntPtr.Zero;
            IntPtr context = IntPtr.Zero;

            if (!WinCrypt.CryptQueryObject(
                WinCrypt.CERT_QUERY_OBJECT_FILE,
                Marshal.StringToHGlobalUni(filePath),
                (WinCrypt.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED
                 | WinCrypt.CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED
                 | WinCrypt.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED),
                WinCrypt.CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                out encodingType,
                out contentType,
                out formatType,
                ref certStore,
                ref cryptMsg,
                ref context))
            {
                Console.WriteLine("Can't read cert at all.");
                throw new InvalidOperationException($"{Marshal.GetLastWin32Error()} - Sigs ain't working.");
            }

            // Get size of the encoded message.
            int cbData = 0;
            if (!WinCrypt.CryptMsgGetParam(
                cryptMsg,
                WinCrypt.CMSG_ENCODED_MESSAGE,
                0,
                IntPtr.Zero,
                ref cbData))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var vData = new byte[cbData];

            // Get the encoded message.
            if (!WinCrypt.CryptMsgGetParam(
                cryptMsg,
                WinCrypt.CMSG_ENCODED_MESSAGE,
                0,
                vData,
                ref cbData))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var signedCms = new SignedCms();
            signedCms.Decode(vData);

            if (signedCms.SignerInfos.Count > 0)
            {
                var signerInfo = signedCms.SignerInfos[0];

                if (signerInfo.Certificate != null)
                {
                    cert = signerInfo.Certificate;
                }
            }

            return cert;
        }

        /// <summary>
        /// Checks if DLL or EXE is signed by Valve.
        /// </summary>
        /// <param name="filePath">The file path.</param>
        /// <returns>System.Boolean.</returns>
        private static int signCount = 0;

        private static bool CheckIfValveSigned(string filePath)
        {
            try
            {
                if (signCount == 0)
                {
                    Console.WriteLine($"Looking at that cert in {filePath}");
                }
                else if (signCount == 5)
                {
                    Console.WriteLine($"Unable to {filePath} after 5 times. Assuming CN emulator.");
                    return false;
                }

                using (var cert = GetDigitalCertificate(filePath))
                {
                    if (cert.Subject == "CN=Valve, O=Valve, L=Bellevue, S=WA, C=US")
                    {
                        Console.WriteLine($"{filePath} is signed.");
                        try
                        {
                            // It's super true but the name info is hard to get.
                            if (cert.GetNameInfo(X509NameType.SimpleName, true) == "Valve")
                            {
                                Console.WriteLine($"{filePath} is super legit.");
                                return true;
                            }
                        }
                        catch
                        {
                            // Ignore.
                        }

                        return true;
                    }
                }
            }
            catch
            {
                // Try again. Keep a temporary counter.
                signCount += 1;
                CheckIfValveSigned(filePath);
                // Ignore.
            }

            return false;
        }

        /// <summary>
        /// Helps iterate through subdirectories to find naughty DLL's.
        /// </summary>
        /// <param name="root"></param>
        /// <param name="searchSubfolders"></param>
        /// <returns></returns>
        private static List<string> GetAllFilesFromFolder(string root, bool searchSubfolders)
        {
            Queue<string> folders = new Queue<string>();
            List<string> files = new List<string>();
            folders.Enqueue(root);
            while (folders.Count != 0)
            {
                string currentFolder = folders.Dequeue();
                try
                {
                    string[] filesInCurrent = System.IO.Directory.GetFiles(currentFolder, "*.*", System.IO.SearchOption.TopDirectoryOnly);
                    files.AddRange(filesInCurrent);
                }
                catch
                {
                    // Do Nothing
                }
                try
                {
                    if (searchSubfolders)
                    {
                        string[] foldersInCurrent = System.IO.Directory.GetDirectories(currentFolder, "*.*", System.IO.SearchOption.TopDirectoryOnly);
                        foreach (string _current in foldersInCurrent)
                        {
                            folders.Enqueue(_current);
                        }
                    }
                }
                catch
                {
                    // Do Nothing
                }
            }
            return files;
        }

        public static void Rename(this FileInfo fileInfo, string newName)
        {
            fileInfo.MoveTo(fileInfo.Directory.FullName + "\\" + newName);
            try
            {
                File.Delete(fileInfo.FullName);
            }
            catch
            {
            }
        }
    }
}