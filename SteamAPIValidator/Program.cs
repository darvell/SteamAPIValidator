using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SteamAPIValidator
{
    internal class Program
    {
        public const string ASSEMBLY_SHA = "729A5065775444990384357A30D7D5A8D5B7EE767206272982E2397366D65C56";

        private static string GetChecksum(string file)
        {
            using (FileStream stream = File.OpenRead(file))
            {
                SHA256Managed sha = new SHA256Managed();
                byte[] checksum = sha.ComputeHash(stream);
                return BitConverter.ToString(checksum).Replace("-", String.Empty);
            }
        }

        public static void Main()
        {
            bool basicCheck = SteamApiValidator.IsValidSteamApiDll();
            bool? advancedCheck = null;
            if (SteamApiValidator.IsSteamClientUsed())
            {
                advancedCheck = SteamApiValidator.IsValidSteamClientDll();
            }

            var dirInfo = new DirectoryInfo(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath);
            string gameName = dirInfo.Name;

            dirInfo = dirInfo.Root;

            if (basicCheck && advancedCheck == true || advancedCheck == null)
            {
                Console.WriteLine("No SteamClient DLL bundled! Great!");
                Console.WriteLine($"Steam API/Client has passed first phase. Running {gameName}.");
            }
            else
            {
                if (!basicCheck)
                {
                    Console.WriteLine("Steam API DLL has been tampered and missing the certificate.");
                }

                if (!advancedCheck == false)
                {
                    Console.WriteLine("Steam client DLL has been tampered.");
                }

                Console.WriteLine("Due to Steam DRM tampering, game will not begin.");
                Console.WriteLine("Press enter to quit.");
                Console.ReadLine();
                Environment.Exit(1);
            }

            Console.WriteLine($"Thank you for support {gameName}! Loading...");

            string assemblyDataPath = Path.Combine(dirInfo.FullName, gameName + "_Data", "Managed", "Assembly-CSharp.dll");
            Directory.SetCurrentDirectory(dirInfo.FullName);
            IntPtr hPrevInstance = IntPtr.Zero;
            NativeMethods.SetDllDirectory(dirInfo.FullName);
            string niceArgs = string.Join(" ", new[] { Assembly.GetExecutingAssembly().CodeBase }.Concat(Environment.GetCommandLineArgs()));

            if (GetChecksum(assemblyDataPath) == ASSEMBLY_SHA)
            {
                niceArgs += " --disable-achievements";
            }

            var dllModule = NativeMethods.LoadLibrary(Path.Combine(dirInfo.FullName + "UnityPlayer.dll"));

            // TODO: Hop in appdomain and be cautious.

            NativeMethods.UnityMain(Process.GetCurrentProcess().Handle, IntPtr.Zero, ref niceArgs, 1);
        }
    }
}