using System;
using System.Runtime.InteropServices;

namespace BasicTest
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, byte[] lpInBuffer, uint nInBufferSize, byte[] lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        static void Main(string[] args)
        {
            Console.WriteLine("=== BasicTest - C# Driver Test Framework ===");
            Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription}");
            Console.WriteLine($"OS: {RuntimeInformation.OSDescription}");
            Console.WriteLine($"Architecture: {RuntimeInformation.OSArchitecture}");
            Console.WriteLine();

            Console.WriteLine("[1] Testing P/Invoke capability...");
            IntPtr handle = LoadLibrary("kernel32.dll");
            if (handle != IntPtr.Zero)
            {
                Console.WriteLine($"    LoadLibrary succeeded: 0x{handle.ToInt64():X}");
                FreeLibrary(handle);
            }
            else
            {
                Console.WriteLine($"    LoadLibrary failed: {Marshal.GetLastWin32Error()}");
            }

            Console.WriteLine();
            Console.WriteLine("[2] Testing unsafe context...");
            unsafe
            {
                int* ptr = stackalloc int[1];
                *ptr = unchecked((int)0xDEADBEEF);
                Console.WriteLine($"    Stack allocation works: 0x{*ptr:X}");
            }

            Console.WriteLine();
            Console.WriteLine("[3] Memory layout verification...");
            Console.WriteLine($"    IntPtr size: {IntPtr.Size} bytes ({(IntPtr.Size == 8 ? "x64" : "x86")})");
            Console.WriteLine($"    Long size: {sizeof(long)} bytes");
            unsafe
            {
                Console.WriteLine($"    Pointer size: {sizeof(void*)} bytes");
            }

            Console.WriteLine();
            Console.WriteLine("[4] Testing IOCTL interface (device may not be loaded)...");
            try
            {
                IntPtr dev = CreateFile("\\\\.\\AntiCheatDriver", 0x80000000 | 0x40000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
                if (dev == new IntPtr(-1))
                {
                    Console.WriteLine($"    Device not available: {Marshal.GetLastWin32Error()} (expected if driver not loaded)");
                }
                else
                {
                    byte[] outBuf = new byte[256];
                    uint returned = 0;
                    bool ok = DeviceIoControl(dev, 0x0022200C, null!, 0, outBuf, (uint)outBuf.Length, out returned, IntPtr.Zero);
                    Console.WriteLine($"    IOCTL_AC_QUERY_INTEGRITY: {(ok ? "OK" : "FAIL")} returned={returned}");
                    CloseHandle(dev);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    IOCTL test skipped: {ex.Message}");
            }

            Console.WriteLine();
            Console.WriteLine("=== BasicTest completed successfully ===");
        }
    }
}