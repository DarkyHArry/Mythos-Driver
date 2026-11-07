using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DriverSigner
{
    internal class Program
    {
        static int Main(string[] args)
        {
            var fileOption = new Option<FileInfo>("--file", "Path to the PE file to sign (.exe, .sys, .dll, etc.)") { IsRequired = true };
            var certOption = new Option<FileInfo>("--cert", "Path to the code signing certificate (.pfx)") { IsRequired = true };
            var passwordOption = new Option<string>("--password", "Certificate password") { IsRequired = true };
            var outputOption = new Option<FileInfo>("--output", "Output path for signed driver") { IsRequired = false };
            var testsignOption = new Option<bool>("--testsign", "Enable test signing mode (for development)") { IsRequired = false };
            var verifyOption = new Option<bool>("--verify", "Verify signature after signing") { IsRequired = false };
            var timestampOption = new Option<string>("--timestamp", "Timestamp server URL") { IsRequired = false };
            var sha256Option = new Option<bool>("--sha256", "Use SHA256 for signing (default: true)") { IsRequired = false };
            var verboseOption = new Option<bool>("--verbose", "Verbose output") { IsRequired = false };

            var rootCommand = new RootCommand("DriverSigner - Sign PE files (.exe, .sys, .dll, etc.) for Windows")
            {
                fileOption, certOption, passwordOption, outputOption,
                testsignOption, verifyOption, timestampOption, sha256Option, verboseOption
            };

            rootCommand.SetHandler(async (InvocationContext context) =>
            {
                var file = context.ParseResult.GetValueForOption(fileOption);
                var cert = context.ParseResult.GetValueForOption(certOption);
                var password = context.ParseResult.GetValueForOption(passwordOption);
                var output = context.ParseResult.GetValueForOption(outputOption);
                var testsign = context.ParseResult.GetValueForOption(testsignOption);
                var verify = context.ParseResult.GetValueForOption(verifyOption);
                var timestamp = context.ParseResult.GetValueForOption(timestampOption);
                var sha256 = context.ParseResult.GetValueForOption(sha256Option);
                var verbose = context.ParseResult.GetValueForOption(verboseOption);

                var exitCode = await SignDriver(file, cert, password, output, testsign, verify, timestamp, sha256, verbose);
                context.ExitCode = exitCode;
            });

            return rootCommand.Invoke(args);
        }

        static async Task<int> SignDriver(
            FileInfo file,
            FileInfo cert,
            string password,
            FileInfo? output,
            bool testsign,
            bool verify,
            string? timestamp,
            bool sha256,
            bool verbose)
        {
            try
            {
                if (verbose)
                {
                    Log("=== DriverSigner - PE File Signing Tool ===");
                    Log($"File: {file.FullName}");
                    Log($"Certificate: {cert.FullName}");
                    Log($"Test Signing: {testsign}");
                    Log($"Verify After Sign: {verify}");
                    Log($"Timestamp Server: {timestamp ?? "default"}");
                    Log($"Algorithm: {(sha256 ? "SHA256" : "SHA1")}");
                    Log("");
                }

                if (!file.Exists)
                {
                    LogError($"File not found: {file.FullName}");
                    return 1;
                }

                if (!cert.Exists)
                {
                    LogError($"Certificate file not found: {cert.FullName}");
                    return 1;
                }

                FileInfo outputFile = output ?? new FileInfo(Path.ChangeExtension(file.FullName, ".signed" + file.Extension));

                if (verbose)
                {
                    Log($"Output: {outputFile.FullName}");
                    Log("");
                }

                X509Certificate2 certificate = LoadCertificate(cert.FullName, password);

                if (verbose)
                {
                    Log($"Certificate loaded: {certificate.Subject}");
                    Log($"Thumbprint: {certificate.Thumbprint}");
                    Log($"Valid: {certificate.NotBefore} to {certificate.NotAfter}");
                    Log($"Has Private Key: {certificate.HasPrivateKey}");
                    Log("");
                }

                if (!certificate.HasPrivateKey)
                {
                    LogError("Certificate does not have a private key");
                    return 1;
                }

                if (DateTime.Now < certificate.NotBefore || DateTime.Now > certificate.NotAfter)
                {
                    LogError("Certificate is not valid for current date");
                    return 1;
                }

                byte[] fileData = File.ReadAllBytes(file.FullName);

                if (verbose)
                {
                    Log($"File size: {fileData.Length} bytes");
                    Log($"File SHA256: {ComputeHash(fileData, HashAlgorithmName.SHA256)}");
                    Log("");
                }

                if (!IsValidDriver(fileData))
                {
                    LogError("Invalid driver file format (not a valid PE image)");
                    return 1;
                }

                if (verbose)
                {
                    Log("Driver PE validation passed");
                    Log("");
                }

                bool success = await SignFile(fileData, certificate, outputFile.FullName, timestamp, sha256, verbose);

                if (!success)
                {
                    LogError("Signing failed");
                    return 1;
                }

                Log($"Driver signed successfully: {outputFile.FullName}");

                if (verify)
                {
                    Log("");
                    Log("Verifying signature...");
                    bool verified = VerifySignature(outputFile.FullName, verbose);
                    if (verified)
                    {
                        Log("Signature verification PASSED");
                    }
                    else
                    {
                        LogError("Signature verification FAILED");
                        return 1;
                    }
                }

                if (testsign)
                {
                    Log("");
                    Log("Test signing mode enabled. To load this driver:");
                    Log("  1. Enable test signing: bcdedit /set testsigning on");
                    Log("  2. Reboot");
                    Log("  3. Load driver with: sc create <name> type= kernel binPath= <path>");
                    Log("  4. Start: sc start <name>");
                }

                return 0;
            }
            catch (Exception ex)
            {
                LogError($"Fatal error: {ex.Message}");
                if (verbose)
                {
                    LogError(ex.StackTrace ?? "");
                }
                return 1;
            }
        }

        static X509Certificate2 LoadCertificate(string path, string password)
        {
            return new X509Certificate2(path, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }

        static bool IsValidDriver(byte[] data)
        {
            if (data.Length < 64)
                return false;

            if (data[0] != 0x4D || data[1] != 0x5A)
                return false;

            int peOffset = BitConverter.ToInt32(data, 0x3C);
            if (peOffset < 0 || peOffset + 4 >= data.Length)
                return false;

            if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45 || data[peOffset + 2] != 0x00 || data[peOffset + 3] != 0x00)
                return false;

            ushort machine = BitConverter.ToUInt16(data, peOffset + 4);
            if (machine != 0x8664)
            {
                LogError($"Driver is not x64 (machine: 0x{machine:X4}). Ring 0 requires x64 drivers.");
                return false;
            }

            ushort characteristics = BitConverter.ToUInt16(data, peOffset + 22);
            bool isDll = (characteristics & 0x2000) != 0;
            bool isDriver = (characteristics & 0x0002) != 0 || isDll;

            return true;
        }

        static async Task<bool> SignFile(byte[] data, X509Certificate2 cert, string outputPath, string? timestampUrl, bool sha256, bool verbose)
        {
            string tempInput = Path.GetTempFileName();
            string tempOutput = Path.GetTempFileName();

            try
            {
                File.WriteAllBytes(tempInput, data);

                string signToolPath = FindSignTool();
                if (string.IsNullOrEmpty(signToolPath))
                {
                    LogError("signtool.exe not found. Install Windows SDK or Visual Studio with Windows SDK.");
                    return false;
                }

                if (verbose)
                {
                    Log($"Using signtool: {signToolPath}");
                }

                string certThumbprint = cert.Thumbprint.Replace(" ", "").ToLower();
                string hashAlg = sha256 ? "sha256" : "sha1";
                string timestampArg = !string.IsNullOrEmpty(timestampUrl)
                    ? $"/tr \"{timestampUrl}\" /td {hashAlg}"
                    : "/tr \"http://timestamp.digicert.com\" /td sha256";

                string arguments = $"sign /v /sha1 {certThumbprint} /fd {hashAlg} {timestampArg} /d \"Ring 0 Driver\" /du \"https://morlsara.io\" \"{tempInput}\"";

                if (verbose)
                {
                    Log($"Arguments: {arguments}");
                }

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = signToolPath,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using Process? process = Process.Start(psi);
                if (process == null)
                {
                    LogError("Failed to start signtool");
                    return false;
                }

                string stdout = await process.StandardOutput.ReadToEndAsync();
                string stderr = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (verbose)
                {
                    Log($"Exit code: {process.ExitCode}");
                    if (!string.IsNullOrEmpty(stdout)) Log($"stdout: {stdout}");
                    if (!string.IsNullOrEmpty(stderr)) Log($"stderr: {stderr}");
                }

                if (process.ExitCode != 0)
                {
                    LogError($"signtool failed with exit code {process.ExitCode}");
                    if (!string.IsNullOrEmpty(stderr)) LogError(stderr);
                    return false;
                }

                byte[] signedData = File.ReadAllBytes(tempInput);
                File.WriteAllBytes(outputPath, signedData);

                return true;
            }
            finally
            {
                try { if (File.Exists(tempInput)) File.Delete(tempInput); } catch { }
                try { if (File.Exists(tempOutput)) File.Delete(tempOutput); } catch { }
            }
        }

        static string? FindSignTool()
        {
            string[] possiblePaths = new[]
            {
                @"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
                @"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
                @"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe",
                @"C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe",
                @"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\signtool.exe",
                @"C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\signtool.exe",
                @"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\signtool.exe",
            };

            foreach (string path in possiblePaths)
            {
                if (File.Exists(path))
                    return path;
            }

            string? windowsKitsRoot = Environment.GetEnvironmentVariable("WindowsSdkDir")
                ?? Environment.GetEnvironmentVariable("WindowsKitRoot");

            if (!string.IsNullOrEmpty(windowsKitsRoot))
            {
                string[] searchPaths = Directory.GetFiles(windowsKitsRoot, "signtool.exe", SearchOption.AllDirectories);
                foreach (string path in searchPaths)
                {
                    if (path.Contains("x64"))
                        return path;
                }
                if (searchPaths.Length > 0)
                    return searchPaths[0];
            }

            return null;
        }

        static bool VerifySignature(string filePath, bool verbose)
        {
            string signToolPath = FindSignTool();
            if (string.IsNullOrEmpty(signToolPath))
            {
                LogError("signtool.exe not found for verification");
                return false;
            }

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = signToolPath,
                Arguments = $"verify /v /pa \"{filePath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using Process? process = Process.Start(psi);
            if (process == null)
                return false;

            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (verbose)
            {
                Log($"Verification exit code: {process.ExitCode}");
                if (!string.IsNullOrEmpty(stdout)) Log(stdout);
                if (!string.IsNullOrEmpty(stderr)) Log(stderr);
            }

            return process.ExitCode == 0 && stdout.Contains("Successfully verified");
        }

        static string ComputeHash(byte[] data, HashAlgorithmName algorithm)
        {
            using HashAlgorithm hash = algorithm == HashAlgorithmName.SHA256 ? SHA256.Create() : SHA1.Create();
            byte[] hashBytes = hash.ComputeHash(data);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }

        static void Log(string message)
        {
            Console.WriteLine(message);
        }

        static void LogError(string message)
        {
            Console.Error.WriteLine($"[ERROR] {message}");
        }
    }
}