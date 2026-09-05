// Debug-only operator harness. No wallet storage, signing, build, or release API.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace YourWallet.ServiceProbe
{
    public static class Harness
    {
        internal const string ServiceName = "YourWalletKeyAgent";
        internal const string Purpose = "service-approval-transport-debug-only";
        internal const string Leaf = "YourWalletServiceProbe";
        internal static readonly string[] Names = { "approval-ui.exe", "key-agent-service-probe.exe", "key-agent-service.exe", "secret-input-ui.exe" };
        internal static readonly string[] Privileges = { "SeAssignPrimaryTokenPrivilege", "SeChangeNotifyPrivilege", "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege" };
        internal static readonly string[] Rights = Privileges.Concat(new[] { "SeServiceLogonRight" }).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        internal const string BaseSddl = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
        internal const string ServiceSddl = "O:BAG:BAD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)";
        private const string CandidatePrefix = "{\"schemaVersion\":1,\"purpose\":\"service-approval-transport-debug-only\",\"architecture\":\"x86_64-pc-windows-msvc\",\"artifacts\":[";

        internal static void Require(bool condition) { if (!condition) throw new InvalidOperationException("SERVICE_PROBE_VALIDATION_FAILED"); }
        internal static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
        internal static string Hash(byte[] bytes) { using (var hash = SHA256.Create()) return Hex(hash.ComputeHash(bytes)); }

        public static void RequireUnelevatedPreparation() { Require(Native.IsUnelevatedPreparation()); }
        public static IDisposable HoldPreparationDirectories(string absolutePath) { return Native.HoldDirectories(absolutePath, false); }
        public static FileStream OpenPreparationFile(string absolutePath) { return Native.OpenPreparationFile(absolutePath); }
        public static void VerifyPreparationFile(FileStream source) { Native.VerifyPreparationFile(source); }
        public static FileStream OpenPreparationBuildFile(string workspace, string name) { return Native.OpenPreparationBuildFile(workspace, name); }
        public static void VerifyPreparationBuildFile(FileStream source) { Native.VerifyPreparationBuildFile(source); }
        public static void CreatePreparationCandidate(string workspace) { Native.CreatePreparationCandidate(workspace); }

        internal interface OperatorOperations
        {
            bool IsElevated();
            void Execute(string action, string workspace);
        }

        private sealed class WindowsOperatorOperations : OperatorOperations
        {
            public bool IsElevated() { return Native.IsElevatedPrimary(); }
            public void Execute(string action, string workspace)
            {
                string programFiles = Native.ProgramFiles();
                string destination = Path.Combine(programFiles, Leaf);
                Require(Path.GetDirectoryName(destination) == programFiles);
                using (var ancestors = Native.HoldDirectories(programFiles, true))
                using (var manager = Native.OpenManager(action == "Install"))
                {
                    if (action == "Install") Install(workspace, destination, manager);
                    else Operate(action, destination, manager);
                }
            }
        }

        internal sealed class Artifact
        {
            internal string Name;
            internal long Bytes;
            internal string Sha256;
        }

        internal static Artifact[] ParseCandidate(byte[] bytes)
        {
            Require(bytes.Length > 0 && bytes.Length <= 2048 && bytes.All(b => b < 128));
            string text = Encoding.ASCII.GetString(bytes);
            var rows = Regex.Matches(text, "\\{\"name\":\"([a-z-]+\\.exe)\",\"bytes\":([1-9][0-9]{0,8}),\"sha256\":\"([0-9a-f]{64})\"\\}", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            Require(rows.Count == 4);
            var artifacts = new Artifact[4];
            var canonical = new StringBuilder(CandidatePrefix);
            for (int i = 0; i < 4; i++)
            {
                var row = rows[i];
                long length;
                Require(row.Groups[1].Value == Names[i] && long.TryParse(row.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out length));
                length = long.Parse(row.Groups[2].Value, CultureInfo.InvariantCulture);
                Require(length > 0 && length <= 512L * 1024 * 1024);
                artifacts[i] = new Artifact { Name = Names[i], Bytes = length, Sha256 = row.Groups[3].Value };
                if (i != 0) canonical.Append(',');
                canonical.Append(row.Value);
            }
            Require(text == canonical.Append("]}\n").ToString());
            return artifacts;
        }

        // The entry point catches everything and returns categories only. No
        // native error, local path, account identity, or file content is output.
        public static string Run(string action, string workspace)
        {
            return RunWith(action, workspace, new WindowsOperatorOperations());
        }

        internal static string RunWith(string action, string workspace, OperatorOperations operations)
        {
            Native.BeginCheckedCleanup();
            try
            {
                Require(action == "Install" || action == "Readback" || action == "Start" || action == "Stop" || action == "Remove");
                if (!operations.IsElevated()) return "SERVICE_PROBE_REQUIRES_ELEVATED_OPERATOR";
                operations.Execute(action, workspace);
                Require(!Native.CleanupFailed);
                return "SERVICE_PROBE_" + action.ToUpperInvariant() + "_PASS_NOT_RELEASE_EVIDENCE";
            }
            catch { return "SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW"; }
        }

        private static void Install(string workspace, string destination, Native.ServiceHandle manager)
        {
            // All source handles and their ancestor directory identities remain
            // held without delete sharing until installation verification ends.
            string candidate = Path.Combine(Path.GetFullPath(workspace), "artifacts", "service-probe-candidate");
            using (var sourceDirectories = Native.HoldDirectories(candidate, false))
            using (var manifest = Native.HeldFile.Open(Path.Combine(candidate, "candidate.json"), false))
            {
                byte[] manifestBytes = manifest.ReadBounded(2048);
                var artifacts = ParseCandidate(manifestBytes);
                var sources = new List<Native.HeldFile>();
                try
                {
                    foreach (var artifact in artifacts)
                    {
                        var source = Native.HeldFile.Open(Path.Combine(candidate, artifact.Name), false);
                        sources.Add(source);
                        source.Verify(artifact.Bytes, artifact.Sha256);
                    }
                    Require(Directory.GetFileSystemEntries(candidate).Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal)
                        .SequenceEqual(Names.Concat(new[] { "candidate.json" }).OrderBy(x => x, StringComparer.Ordinal)));
                    Native.RequireServiceAbsent(manager);
                    Native.CreateProtectedDirectory(destination);
                    // From this point, failure deliberately retains the exact
                    // protected partial fixture. No uncertain auto-deletion.
                    using (var directory = Native.HoldDirectories(destination, true))
                    {
                        for (int i = 0; i < artifacts.Length; i++) sources[i].CopyNew(Path.Combine(destination, artifacts[i].Name), BaseSddl);
                        Native.WriteNew(Path.Combine(destination, "candidate.json"), manifestBytes, BaseSddl);
                        using (var service = Native.CreateService(manager, destination))
                        {
                            Native.SetExactSecurity(service.DangerousGetHandle(), 2, ServiceSddl);
                            string serviceSid = Native.ServiceSid();
                            string approvalSid = Native.PackageSid("YourWallet.ApprovalFrontend.LPAC.v1");
                            string secretSid = Native.PackageSid("YourWallet.SecretInputFrontend.LPAC.v1");
                            Require(serviceSid.StartsWith("S-1-5-80-", StringComparison.Ordinal) && approvalSid != secretSid);
                            string[] baseline = Native.ReadRights(serviceSid);
                            Require(baseline.All(x => Rights.Contains(x, StringComparer.Ordinal)));
                            string[] added = Rights.Except(baseline, StringComparer.Ordinal).ToArray();
                            // Journal the exact planned additions before LSA
                            // mutation. Preexisting/SCM-created rights are never
                            // removed, including an already present logon right.
                            string journal = "YW_SERVICE_PROBE_OWNED_V1\n" + directory.LeafIdentity + "\n" + Hash(manifestBytes) + "\n" +
                                string.Join(",", baseline) + "\n" + string.Join(",", added) + "\n";
                            Native.WriteNew(Path.Combine(destination, "ownership.txt"), Encoding.ASCII.GetBytes(journal), BaseSddl);
                            Native.AddRights(serviceSid, added);
                            Require(Native.ReadRights(serviceSid).SequenceEqual(Rights));
                            Native.Configure(service);
                            Native.ApplyArtifactSecurity(destination, serviceSid, approvalSid, secretSid);
                            Native.VerifyService(service, destination);
                            VerifyOwned(destination, directory.LeafIdentity, service);
                        }
                    }
                }
                finally { foreach (var source in sources) source.Dispose(); }
            }
        }

        private static string[] VerifyOwned(string destination, string directoryIdentity, Native.ServiceHandle service)
        {
            Native.VerifyService(service, destination);
            string serviceSid = Native.ServiceSid();
            Require(Native.ReadRights(serviceSid).SequenceEqual(Rights));
            return VerifyOwnedFiles(destination, directoryIdentity, serviceSid);
        }

        private static string[] VerifyOwnedFiles(string destination, string directoryIdentity, string serviceSid)
        {
            Native.VerifyArtifactSecurity(destination, serviceSid,
                Native.PackageSid("YourWallet.ApprovalFrontend.LPAC.v1"), Native.PackageSid("YourWallet.SecretInputFrontend.LPAC.v1"));
            using (var manifest = Native.HeldFile.Open(Path.Combine(destination, "candidate.json"), false))
            using (var ownership = Native.HeldFile.Open(Path.Combine(destination, "ownership.txt"), false))
            {
                byte[] bytes = manifest.ReadBounded(2048);
                var artifacts = ParseCandidate(bytes);
                byte[] journalBytes = ownership.ReadBounded(2048);
                Require(journalBytes.All(b => b < 128));
                string[] journal = Encoding.ASCII.GetString(journalBytes).Split('\n');
                Require(journal.Length == 6 && journal[0] == "YW_SERVICE_PROBE_OWNED_V1" && journal[1] == directoryIdentity && journal[2] == Hash(bytes) && journal[5] == "");
                string[] baseline = journal[3] == "" ? new string[0] : journal[3].Split(',');
                string[] added = journal[4] == "" ? new string[0] : journal[4].Split(',');
                Require(baseline.SequenceEqual(baseline.Distinct().OrderBy(x => x, StringComparer.Ordinal)) &&
                    added.SequenceEqual(added.Distinct().OrderBy(x => x, StringComparer.Ordinal)) &&
                    !baseline.Intersect(added, StringComparer.Ordinal).Any() &&
                    baseline.Concat(added).OrderBy(x => x, StringComparer.Ordinal).SequenceEqual(Rights));
                foreach (var artifact in artifacts)
                    using (var file = Native.HeldFile.Open(Path.Combine(destination, artifact.Name), false)) file.Verify(artifact.Bytes, artifact.Sha256);
                Require(Directory.GetFileSystemEntries(destination).Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal)
                    .SequenceEqual(Names.Concat(new[] { "candidate.json", "ownership.txt" }).OrderBy(x => x, StringComparer.Ordinal)));
                return added;
            }
        }

        private static void Operate(string action, string destination, Native.ServiceHandle manager)
        {
            string retainedIdentity;
            string retainedServiceSid;
            string[] retainedAdditions;
            using (var directory = Native.HoldDirectories(destination, true))
            using (var service = Native.OpenOwnedService(manager))
            {
                string[] added = VerifyOwned(destination, directory.LeafIdentity, service);
                if (action == "Readback") return;
                if (action == "Start") { Native.Start(service); return; }
                if (action == "Stop") { Native.Stop(service); return; }
                Require(action == "Remove" && Native.Status(service) == 1);
                // Re-read before mutations; require stopped rather than
                // silently stopping somebody else's changed configuration.
                VerifyOwned(destination, directory.LeafIdentity, service);
                string serviceSid = Native.ServiceSid();
                retainedIdentity = directory.LeafIdentity;
                retainedServiceSid = serviceSid;
                retainedAdditions = added;
                string[] baseline = Rights.Except(added, StringComparer.Ordinal).ToArray();
                Native.RemoveRights(serviceSid, added);
                Require(Native.ReadRights(serviceSid).SequenceEqual(baseline));
                Native.Delete(service);
                // SCM deletion is deferred until this final handle is closed.
            }
            Native.RequireServiceAbsent(manager);
            using (var directory = Native.HoldDirectories(destination, true))
            {
                Require(directory.LeafIdentity == retainedIdentity &&
                    VerifyOwnedFiles(destination, retainedIdentity, retainedServiceSid).SequenceEqual(retainedAdditions));
                // Only exact verified file leaves are removed, never a
                // recursive collection. Extra entries leave the root intact.
                foreach (string name in Names.Concat(new[] { "candidate.json", "ownership.txt" }))
                    Native.DeleteExactFile(Path.Combine(destination, name));
            }
            Native.RemoveExactDirectory(destination, retainedIdentity);
        }

        public static int SelfTest()
        {
            int checks = 0;
            string rows = string.Join(",", Names.Select(n => "{\"name\":\"" + n + "\",\"bytes\":1,\"sha256\":\"" + new string('a', 64) + "\"}"));
            string canonical = CandidatePrefix + rows + "]}\n";
            Require(ParseCandidate(Encoding.ASCII.GetBytes(canonical)).Length == 4); checks++;
            foreach (string invalid in new[] { canonical.TrimEnd('\n'), canonical + "\n", " " + canonical, canonical.Replace("\"bytes\":1", "\"bytes\":0"), canonical.Replace("\"bytes\":1", "\"bytes\":01"), canonical.Replace("\"bytes\":1", "\"bytes\":536870913"), canonical.Replace("approval-ui.exe", "../approval-ui.exe"), canonical.Replace("approval-ui.exe", "APPROVAL-UI.exe"), canonical.Replace("key-agent-service-probe.exe", "approval-ui.exe"), canonical.Replace("x86_64-pc-windows-msvc", "release"), canonical.Replace("schemaVersion\":1", "schemaVersion\":2"), canonical.Replace("\"bytes\":1", "\"bytes\":1,\"extra\":1"), canonical.Replace(new string('a', 64), new string('A', 64)) })
            {
                bool rejected = false;
                try { ParseCandidate(Encoding.ASCII.GetBytes(invalid)); } catch { rejected = true; }
                Require(rejected); checks++;
            }
            Require(!Privileges.Contains("SeDebugPrivilege") && !Privileges.Contains("SeTcbPrivilege") && !Privileges.Contains("SeBackupPrivilege")); checks++;
            Require(Rights.Length == 5 && Rights.Distinct().Count() == 5); checks++;
            foreach (string action in new[] { "Install", "Readback", "Start", "Stop", "Remove" })
            {
                var denied = new FakeOperatorOperations();
                Require(RunWith(action, "untrusted-marker-never-output", denied) == "SERVICE_PROBE_REQUIRES_ELEVATED_OPERATOR" && denied.Queries == 1 && denied.Executions == 0); checks++;
                var allowed = new FakeOperatorOperations { Elevated = true };
                Require(RunWith(action, "untrusted-marker-never-output", allowed) == "SERVICE_PROBE_" + action.ToUpperInvariant() + "_PASS_NOT_RELEASE_EVIDENCE" && allowed.Queries == 1 && allowed.Executions == 1); checks++;
            }
            var unknown = new FakeOperatorOperations { Elevated = true };
            Require(RunWith("untrusted-marker-never-output", "", unknown) == "SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW" && unknown.Queries == 0 && unknown.Executions == 0); checks++;
            var broken = new FakeOperatorOperations { Elevated = true, Fail = true };
            Require(RunWith("Install", "", broken) == "SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW" && broken.Executions == 1); checks++;
            var failedCleanup = new FakeOperatorOperations { Elevated = true, FailCleanup = true };
            Require(RunWith("Remove", "", failedCleanup) == "SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW" && failedCleanup.Executions == 1); checks++;
            Require(Native.InteropLayoutsAreExact()); checks++;
            return checks;
        }

        private sealed class FakeOperatorOperations : OperatorOperations
        {
            internal bool Elevated, Fail, FailCleanup;
            internal int Queries, Executions;
            public bool IsElevated() { Queries++; return Elevated; }
            public void Execute(string action, string workspace) { Executions++; if (FailCleanup) Native.RecordCleanupFailure(); if (Fail) throw new InvalidOperationException("untrusted-marker-never-output"); }
        }
    }

    internal static class Native
    {
        // All operator work is synchronous on one managed thread. Explicit
        // using/finally releases record failure without throwing from a
        // SafeHandle finalizer; the outer dispatcher cannot return PASS after
        // a failed explicit SCM/LSA/native-allocation release.
        [ThreadStatic] private static bool cleanupFailed;
        internal static bool CleanupFailed { get { return cleanupFailed; } }
        internal static void BeginCheckedCleanup() { cleanupFailed = false; }
        internal static void RecordCleanupFailure() { cleanupFailed = true; }
        private static void CheckCleanup(bool accepted) { if (!accepted) RecordCleanupFailure(); }
        internal static bool InteropLayoutsAreExact()
        {
            return IntPtr.Size == 8 && Marshal.SizeOf(typeof(byte)) == 1 &&
                Marshal.SizeOf(typeof(FileInfo)) == 52 && Marshal.SizeOf(typeof(ServiceStatus)) == 36 &&
                Marshal.SizeOf(typeof(SecurityAttributes)) == 24 && Marshal.SizeOf(typeof(ServiceConfig)) == 64 &&
                Marshal.SizeOf(typeof(LsaAttributes)) == 48 && Marshal.SizeOf(typeof(LsaString)) == 16;
        }
        [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { internal int Length; internal IntPtr Descriptor; internal int Inherit; }
        [StructLayout(LayoutKind.Sequential, Pack = 4)] private struct FileInfo { internal uint Attributes; internal long Creation; internal long Access; internal long Write; internal uint Volume; internal uint SizeHigh; internal uint SizeLow; internal uint Links; internal uint IndexHigh; internal uint IndexLow; }
        [StructLayout(LayoutKind.Sequential)] private struct ServiceConfig { internal uint Type, Start, Error; internal IntPtr Binary, Group; internal uint Tag; internal IntPtr Dependencies, Account, Display; }
        [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { internal uint Type, State, Accepted, Exit, Specific, Checkpoint, WaitHint, ProcessId, Flags; }
        [StructLayout(LayoutKind.Sequential)] private struct LsaAttributes { internal uint Length; internal IntPtr Root, Name; internal uint Attributes; internal IntPtr Descriptor, Qos; }
        [StructLayout(LayoutKind.Sequential)] private struct LsaString { internal ushort Length, MaximumLength; internal IntPtr Buffer; }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, ref SecurityAttributes security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CreateDirectoryW(string path, ref SecurityAttributes security);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetFileInformationByHandle(SafeFileHandle file, uint kind, ref byte information, uint bytes);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentThread();
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeFileHandle token);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenThreadToken(IntPtr thread, uint access, bool asSelf, out SafeFileHandle token);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(SafeFileHandle token, int kind, out int value, int bytes, out int needed);
        [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)] private static extern bool GetTokenInformationBytes(SafeFileHandle token, int kind, IntPtr value, int bytes, out int needed);
        [DllImport("shell32.dll")] private static extern int SHGetKnownFolderPath(ref Guid folder, uint flags, IntPtr token, out IntPtr path);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint bytes);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(IntPtr handle, uint kind, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")] private static extern uint SetSecurityInfo(IntPtr handle, uint kind, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetSecurityDescriptorOwner(IntPtr sd, out IntPtr owner, out bool defaulted);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetSecurityDescriptorGroup(IntPtr sd, out IntPtr group, out bool defaulted);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool defaulted);
        [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr sd);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool LookupAccountNameW(string system, string name, byte[] sid, ref uint sidBytes, StringBuilder domain, ref uint domainChars, out uint use);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
        [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenSCManagerW(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenServiceW(ServiceHandle manager, string name, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle CreateServiceW(ServiceHandle manager, string name, string display, uint access, uint type, uint start, uint error, string binary, string group, IntPtr tag, string dependencies, string account, string password);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CloseServiceHandle(IntPtr handle);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ChangeServiceConfig2W(ServiceHandle service, uint level, IntPtr information);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryServiceConfigW(ServiceHandle service, IntPtr buffer, uint bytes, out uint needed);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryServiceConfig2W(ServiceHandle service, uint level, IntPtr buffer, uint bytes, out uint needed);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool QueryServiceStatusEx(ServiceHandle service, uint level, out ServiceStatus status, uint bytes, out uint needed);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool StartServiceW(ServiceHandle service, uint count, IntPtr arguments);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool ControlService(ServiceHandle service, uint control, out ServiceStatus status);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DeleteService(ServiceHandle service);
        [DllImport("advapi32.dll")] private static extern uint LsaOpenPolicy(IntPtr system, ref LsaAttributes attributes, uint access, out IntPtr policy);
        [DllImport("advapi32.dll")] private static extern uint LsaClose(IntPtr policy);
        [DllImport("advapi32.dll")] private static extern uint LsaEnumerateAccountRights(IntPtr policy, byte[] sid, out IntPtr rights, out uint count);
        [DllImport("advapi32.dll")] private static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, LsaString[] rights, uint count);
        [DllImport("advapi32.dll")] private static extern uint LsaRemoveAccountRights(IntPtr policy, byte[] sid, [MarshalAs(UnmanagedType.U1)] bool all, LsaString[] rights, uint count);
        [DllImport("advapi32.dll")] private static extern uint LsaFreeMemory(IntPtr memory);
        [DllImport("advapi32.dll")] private static extern uint LsaNtStatusToWinError(uint status);

        internal sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private ServiceHandle() : base(true) { }
            protected override bool ReleaseHandle() { bool closed = CloseServiceHandle(handle); CheckCleanup(closed); return closed; }
        }

        private sealed class Descriptor : IDisposable
        {
            internal IntPtr Pointer;
            internal Descriptor(string sddl) { uint bytes; Harness.Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out Pointer, out bytes)); }
            public void Dispose() { if (Pointer != IntPtr.Zero) { CheckCleanup(LocalFree(Pointer) == IntPtr.Zero); Pointer = IntPtr.Zero; } }
        }

        internal static bool IsElevatedPrimary()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT || !Environment.Is64BitProcess || !Environment.UserInteractive) return false;
            SafeFileHandle thread;
            if (OpenThreadToken(GetCurrentThread(), 8, true, out thread)) { thread.Dispose(); return false; }
            int error = Marshal.GetLastWin32Error();
            if (thread != null) thread.Dispose();
            if (error != 1008) return false;
            SafeFileHandle token;
            if (!OpenProcessToken(GetCurrentProcess(), 8, out token)) return false;
            using (token)
            {
                int elevation, kind, session, needed;
                if (!GetTokenInformation(token, 20, out elevation, 4, out needed) || needed != 4 || elevation != 1 ||
                    !GetTokenInformation(token, 8, out kind, 4, out needed) || needed != 4 || kind != 1 ||
                    !GetTokenInformation(token, 12, out session, 4, out needed) || needed != 4 || session == 0) return false;
                using (var identity = WindowsIdentity.GetCurrent()) return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        internal static bool IsUnelevatedPreparation()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT || !Environment.Is64BitProcess || !Environment.UserInteractive) return false;
            SafeFileHandle thread;
            if (OpenThreadToken(GetCurrentThread(), 8, true, out thread)) { thread.Dispose(); return false; }
            int error = Marshal.GetLastWin32Error(); if (thread != null) thread.Dispose(); if (error != 1008) return false;
            SafeFileHandle token; if (!OpenProcessToken(GetCurrentProcess(), 8, out token)) return false;
            using (token)
            {
                int elevation, kind, session, needed;
                if (!GetTokenInformation(token, 20, out elevation, 4, out needed) || needed != 4 || elevation != 0 ||
                    !GetTokenInformation(token, 8, out kind, 4, out needed) || needed != 4 || kind != 1 ||
                    !GetTokenInformation(token, 12, out session, 4, out needed) || needed != 4 || session == 0 || !HasMediumIntegrity(token)) return false;
                using (var identity = WindowsIdentity.GetCurrent()) return !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static bool HasMediumIntegrity(SafeFileHandle token)
        {
            const int capacity = 128;
            IntPtr buffer = Marshal.AllocHGlobal(capacity);
            try
            {
                int needed;
                if (!GetTokenInformationBytes(token, 25, buffer, capacity, out needed) || needed < IntPtr.Size + 4 || needed > capacity) return false;
                IntPtr sid = Marshal.ReadIntPtr(buffer);
                long offset = sid.ToInt64() - buffer.ToInt64();
                if (offset < IntPtr.Size + 4 || offset + 12 > needed || Marshal.ReadByte(sid) != 1 || Marshal.ReadByte(sid, 1) != 1) return false;
                for (int i = 2; i < 7; i++) if (Marshal.ReadByte(sid, i) != 0) return false;
                return Marshal.ReadByte(sid, 7) == 16 && Marshal.ReadInt32(sid, 8) == 0x2000;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        internal static FileStream OpenPreparationFile(string path)
        {
            return new FileStream(OpenFile(path, false, false, null), FileAccess.Read);
        }

        internal static void VerifyPreparationFile(FileStream source)
        {
            FileInfo info = new FileInfo();
            Harness.Require(source != null && source.CanRead && !source.CanWrite && GetFileInformationByHandle(source.SafeFileHandle, out info));
            Harness.Require((info.Attributes & 0x410) == 0 && info.Links == 1 && source.Length > 0 && source.Length <= 512L * 1024 * 1024);
        }

        // Cargo normally hardlinks its reported debug executable to one deps
        // alias. This separate, unelevated build-only boundary permits that
        // exact bounded link count while READ/shareREAD denies writes through
        // either alias and deletion of the opened name. Windows can delete an
        // unopened alias; recorded link-count drift is rejected on revalidation.
        // Installer/candidate opens remain strict single-link; this API cannot
        // choose any other artifact or directory.
        private sealed class PreparationBuildIdentity
        {
            internal readonly string FileIdentity;
            internal readonly long Length;
            internal readonly uint Links;
            internal PreparationBuildIdentity(string identity, long length, uint links)
            { FileIdentity = identity; Length = length; Links = links; }
        }
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<FileStream, PreparationBuildIdentity> PreparationBuildOwners =
            new System.Runtime.CompilerServices.ConditionalWeakTable<FileStream, PreparationBuildIdentity>();

        internal static FileStream OpenPreparationBuildFile(string workspace, string name)
        {
            Harness.Require(IsUnelevatedPreparation() && Harness.Names.Contains(name, StringComparer.Ordinal));
            string root = Path.GetFullPath(workspace);
            Harness.Require(root == workspace);
            string directory = Path.Combine(root, "target", "service-probe-build", "x86_64-pc-windows-msvc", "debug");
            using (var held = HoldDirectories(directory, false))
            {
                var attributes = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)) };
                var handle = CreateFileW(Path.Combine(directory, name), 0x80000000 | 0x20000, 1, ref attributes, 3, 0x00200000, IntPtr.Zero);
                FileStream source = null;
                try
                {
                    FileInfo info = new FileInfo();
                    Harness.Require(!handle.IsInvalid && GetFileInformationByHandle(handle, out info));
                    Harness.Require((info.Attributes & 0x410) == 0 && (info.Links == 1 || info.Links == 2));
                    source = new FileStream(handle, FileAccess.Read);
                    Harness.Require(source.Length > 0 && source.Length <= 512L * 1024 * 1024);
                    PreparationBuildOwners.Add(source, new PreparationBuildIdentity(PreparationBuildFileIdentity(info), source.Length, info.Links));
                    VerifyPreparationBuildFile(source);
                    return source;
                }
                catch { if (source != null) source.Dispose(); else handle.Dispose(); throw; }
            }
        }

        internal static void VerifyPreparationBuildFile(FileStream source)
        {
            Harness.Require(IsUnelevatedPreparation());
            PreparationBuildIdentity expected;
            Harness.Require(source != null && source.CanRead && !source.CanWrite);
            Harness.Require(PreparationBuildOwners.TryGetValue(source, out expected));
            FileInfo info;
            Harness.Require(GetFileInformationByHandle(source.SafeFileHandle, out info));
            Harness.Require((info.Attributes & 0x410) == 0 && (info.Links == 1 || info.Links == 2) &&
                info.Links == expected.Links && PreparationBuildFileIdentity(info) == expected.FileIdentity &&
                source.Length == expected.Length && source.Length > 0 && source.Length <= 512L * 1024 * 1024);
        }

        private static string PreparationBuildFileIdentity(FileInfo info)
        {
            Harness.Require((info.Attributes & 0x410) == 0 && (info.Links == 1 || info.Links == 2));
            return info.Volume.ToString("x8", CultureInfo.InvariantCulture) + info.IndexHigh.ToString("x8", CultureInfo.InvariantCulture) + info.IndexLow.ToString("x8", CultureInfo.InvariantCulture);
        }

        internal static void CreatePreparationCandidate(string workspace)
        {
            Harness.Require(IsUnelevatedPreparation());
            string root = Path.GetFullPath(workspace);
            string parent = Path.Combine(root, "artifacts");
            using (var held = HoldDirectories(parent, false))
            {
                var security = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)) };
                Harness.Require(CreateDirectoryW(Path.Combine(parent, "service-probe-candidate"), ref security));
            }
        }

        internal static string ProgramFiles()
        {
            Guid folder = new Guid("905e63b6-c1bf-494e-b29c-65b732d3d21a");
            IntPtr value;
            Harness.Require(SHGetKnownFolderPath(ref folder, 0, IntPtr.Zero, out value) == 0 && value != IntPtr.Zero);
            try
            {
                string path = Marshal.PtrToStringUni(value);
                Harness.Require(path.Length > 3 && Path.IsPathRooted(path) && !path.StartsWith("\\", StringComparison.Ordinal) && Path.GetFullPath(path) == path);
                return path;
            }
            finally { Marshal.FreeCoTaskMem(value); }
        }

        private static SafeFileHandle OpenFile(string path, bool directory, bool writable, string createSddl)
        {
            Descriptor descriptor = createSddl == null ? null : new Descriptor(createSddl);
            try
            {
                var attributes = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)), Descriptor = descriptor == null ? IntPtr.Zero : descriptor.Pointer };
                uint access = 0x80000000 | 0x20000;
                if (writable) access |= 0x40000000 | 0x40000 | 0x80000;
                var handle = CreateFileW(path, access, directory ? 3U : 1U, ref attributes, createSddl == null ? 3U : 1U, 0x00200000 | (directory ? 0x02000000U : 0U), IntPtr.Zero);
                Harness.Require(!handle.IsInvalid);
                FileInfo info;
                if (!GetFileInformationByHandle(handle, out info) || (info.Attributes & 0x400) != 0 || (((info.Attributes & 0x10) != 0) != directory) || (!directory && info.Links != 1))
                { handle.Dispose(); throw new InvalidOperationException("SERVICE_PROBE_FILE_IDENTITY_FAILED"); }
                return handle;
            }
            finally { if (descriptor != null) descriptor.Dispose(); }
        }

        private static string Identity(SafeFileHandle file)
        {
            FileInfo info;
            Harness.Require(GetFileInformationByHandle(file, out info));
            Harness.Require((info.Attributes & 0x400) == 0 && ((info.Attributes & 0x10) != 0 || info.Links == 1));
            return info.Volume.ToString("x8", CultureInfo.InvariantCulture) + info.IndexHigh.ToString("x8", CultureInfo.InvariantCulture) + info.IndexLow.ToString("x8", CultureInfo.InvariantCulture);
        }

        internal sealed class DirectoryLease : IDisposable
        {
            private readonly List<SafeFileHandle> handles;
            internal readonly string LeafIdentity;
            internal DirectoryLease(List<SafeFileHandle> owned) { handles = owned; LeafIdentity = Identity(owned.Last()); }
            public void Dispose() { foreach (var handle in handles.AsEnumerable().Reverse()) handle.Dispose(); }
        }

        internal static DirectoryLease HoldDirectories(string path, bool protectedPath)
        {
            Harness.Require(Path.GetFullPath(path) == path && Path.GetPathRoot(path).Length == 3);
            var handles = new List<SafeFileHandle>();
            try
            {
                string current = Path.GetPathRoot(path);
                foreach (string part in path.Substring(current.Length).Split(Path.DirectorySeparatorChar))
                {
                    Harness.Require(part.Length > 0 && part != "." && part != ".." && !part.EndsWith(".", StringComparison.Ordinal) && !part.EndsWith(" ", StringComparison.Ordinal));
                    current = Path.Combine(current, part);
                    var handle = OpenFile(current, true, false, null);
                    handles.Add(handle);
                    if (protectedPath) RequireNoUnprivilegedWrite(handle.DangerousGetHandle());
                }
                Harness.Require(handles.Count > 0);
                return new DirectoryLease(handles);
            }
            catch { foreach (var handle in handles) handle.Dispose(); throw; }
        }

        internal sealed class HeldFile : IDisposable
        {
            private readonly SafeFileHandle handle;
            private readonly FileStream stream;
            private readonly string identity;
            private HeldFile(SafeFileHandle owned, bool writable) { handle = owned; identity = Identity(owned); stream = new FileStream(owned, writable ? FileAccess.ReadWrite : FileAccess.Read); }
            internal static HeldFile Open(string path, bool writable) { return new HeldFile(OpenFile(path, false, writable, null), writable); }
            internal byte[] ReadBounded(int maximum)
            {
                Harness.Require(stream.Length > 0 && stream.Length <= maximum);
                stream.Position = 0;
                byte[] bytes = new byte[(int)stream.Length];
                int offset = 0;
                while (offset < bytes.Length) { int count = stream.Read(bytes, offset, bytes.Length - offset); Harness.Require(count > 0); offset += count; }
                Harness.Require(stream.ReadByte() == -1 && Identity(handle) == identity);
                return bytes;
            }
            internal void Verify(long length, string hash)
            {
                Harness.Require(stream.Length == length && Identity(handle) == identity);
                stream.Position = 0;
                using (var sha = SHA256.Create()) Harness.Require(Harness.Hex(sha.ComputeHash(stream)) == hash);
                Harness.Require(stream.Length == length && Identity(handle) == identity);
            }
            internal void CopyNew(string path, string sddl)
            {
                using (var output = new HeldFile(OpenFile(path, false, true, sddl), true))
                {
                    stream.Position = 0;
                    stream.CopyTo(output.stream, 65536);
                    output.stream.Flush(true);
                    Harness.Require(Identity(handle) == identity);
                    VerifyExactSecurity(output.handle.DangerousGetHandle(), 1, sddl);
                }
            }
            public void Dispose() { stream.Dispose(); }
        }

        internal static void WriteNew(string path, byte[] bytes, string sddl)
        {
            using (var file = OpenFile(path, false, true, sddl))
            using (var stream = new FileStream(file, FileAccess.ReadWrite)) { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); VerifyExactSecurity(file.DangerousGetHandle(), 1, sddl); }
        }

        private static RawSecurityDescriptor ReadSecurity(IntPtr handle, uint kind)
        {
            IntPtr owner, group, dacl, sacl, sd;
            Harness.Require(GetSecurityInfo(handle, kind, 7, out owner, out group, out dacl, out sacl, out sd) == 0);
            try { uint length = GetSecurityDescriptorLength(sd); Harness.Require(length > 0 && length < 65536); byte[] bytes = new byte[length]; Marshal.Copy(sd, bytes, 0, (int)length); return new RawSecurityDescriptor(bytes, 0); }
            finally { CheckCleanup(LocalFree(sd) == IntPtr.Zero); }
        }

        private static string AclShape(RawAcl acl)
        {
            Harness.Require(acl != null);
            byte[] bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return Convert.ToBase64String(bytes);
        }

        private static void VerifyExactSecurity(IntPtr handle, uint kind, string sddl)
        {
            var actual = ReadSecurity(handle, kind); var expected = new RawSecurityDescriptor(sddl);
            Harness.Require(actual.Owner.Equals(expected.Owner) && actual.Group.Equals(expected.Group) &&
                (actual.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 && AclShape(actual.DiscretionaryAcl) == AclShape(expected.DiscretionaryAcl));
        }

        internal static void SetExactSecurity(IntPtr handle, uint kind, string sddl)
        {
            using (var sd = new Descriptor(sddl))
            {
                IntPtr owner = IntPtr.Zero, group = IntPtr.Zero, dacl = IntPtr.Zero; bool ignored, present = false;
                Harness.Require(GetSecurityDescriptorOwner(sd.Pointer, out owner, out ignored) && GetSecurityDescriptorGroup(sd.Pointer, out group, out ignored) && GetSecurityDescriptorDacl(sd.Pointer, out present, out dacl, out ignored) && present);
                Harness.Require(SetSecurityInfo(handle, kind, 0x80000007, owner, group, dacl, IntPtr.Zero) == 0);
            }
            VerifyExactSecurity(handle, kind, sddl);
        }

        private static void RequireNoUnprivilegedWrite(IntPtr directory)
        {
            var descriptor = ReadSecurity(directory, 1);
            var trusted = new[] { "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" };
            Harness.Require(descriptor.Owner != null && trusted.Contains(descriptor.Owner.Value) && descriptor.DiscretionaryAcl != null);
            foreach (GenericAce ace in descriptor.DiscretionaryAcl)
            {
                var common = ace as CommonAce;
                Harness.Require(common != null && !common.IsCallback);
                if (common.AceQualifier == AceQualifier.AccessAllowed && (common.AceFlags & AceFlags.InheritOnly) == 0 &&
                    (common.AccessMask & unchecked((int)0x500D0156)) != 0) Harness.Require(trusted.Contains(common.SecurityIdentifier.Value));
            }
        }

        internal static void CreateProtectedDirectory(string path)
        {
            using (var sd = new Descriptor(Harness.BaseSddl))
            {
                var attributes = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)), Descriptor = sd.Pointer };
                Harness.Require(CreateDirectoryW(path, ref attributes));
            }
            using (var handle = OpenFile(path, true, false, null)) VerifyExactSecurity(handle.DangerousGetHandle(), 1, Harness.BaseSddl);
        }

        internal static string ServiceSid()
        {
            uint bytes = 0, chars = 0, use;
            LookupAccountNameW(null, "NT SERVICE\\" + Harness.ServiceName, null, ref bytes, null, ref chars, out use);
            Harness.Require(Marshal.GetLastWin32Error() == 122 && bytes >= 8 && bytes <= 68 && chars <= 256);
            byte[] sid = new byte[bytes]; var domain = new StringBuilder((int)chars);
            Harness.Require(LookupAccountNameW(null, "NT SERVICE\\" + Harness.ServiceName, sid, ref bytes, domain, ref chars, out use));
            return new SecurityIdentifier(sid, 0).Value;
        }

        internal static string PackageSid(string name)
        {
            IntPtr sid; Harness.Require(DeriveAppContainerSidFromAppContainerName(name, out sid) == 0 && sid != IntPtr.Zero);
            try { string value = new SecurityIdentifier(sid).Value; Harness.Require(value.StartsWith("S-1-15-2-", StringComparison.Ordinal)); return value; }
            finally { CheckCleanup(FreeSid(sid) == IntPtr.Zero); }
        }

        private static string ArtifactSddl(string name, string service, string approval, string secret)
        {
            string sddl = Harness.BaseSddl + "(A;;0x1200a9;;;" + service + ")";
            if (name == "approval-ui.exe") sddl += "(A;;0x1200a9;;;" + approval + ")";
            if (name == "secret-input-ui.exe") sddl += "(A;;0x1200a9;;;" + secret + ")";
            if (name == "directory") sddl += "(A;;0x1200a9;;;" + approval + ")(A;;0x1200a9;;;" + secret + ")";
            return sddl;
        }

        internal static void ApplyArtifactSecurity(string destination, string service, string approval, string secret)
        {
            foreach (string name in Harness.Names.Concat(new[] { "candidate.json", "ownership.txt", "directory" }))
            {
                bool directory = name == "directory";
                string sddl = (name == "candidate.json" || name == "ownership.txt") ? Harness.BaseSddl : ArtifactSddl(name, service, approval, secret);
                using (var file = OpenFile(directory ? destination : Path.Combine(destination, name), directory, true, null)) SetExactSecurity(file.DangerousGetHandle(), 1, sddl);
            }
        }

        internal static void VerifyArtifactSecurity(string destination, string service, string approval, string secret)
        {
            foreach (string name in Harness.Names.Concat(new[] { "candidate.json", "ownership.txt", "directory" }))
            {
                bool directory = name == "directory";
                string sddl = (name == "candidate.json" || name == "ownership.txt") ? Harness.BaseSddl : ArtifactSddl(name, service, approval, secret);
                using (var file = OpenFile(directory ? destination : Path.Combine(destination, name), directory, false, null)) VerifyExactSecurity(file.DangerousGetHandle(), 1, sddl);
            }
        }

        internal static ServiceHandle OpenManager(bool create) { var manager = OpenSCManagerW(null, null, create ? 3U : 1U); Harness.Require(!manager.IsInvalid); return manager; }
        internal static void RequireServiceAbsent(ServiceHandle manager)
        {
            using (var existing = OpenServiceW(manager, Harness.ServiceName, 1)) { int error = Marshal.GetLastWin32Error(); Harness.Require(existing.IsInvalid && error == 1060); }
        }
        internal static ServiceHandle CreateService(ServiceHandle manager, string destination)
        {
            var service = CreateServiceW(manager, Harness.ServiceName, Harness.ServiceName, 0xF01FF, 0x10, 3, 1, "\"" + Path.Combine(destination, "key-agent-service.exe") + "\"", null, IntPtr.Zero, null, "NT SERVICE\\" + Harness.ServiceName, null);
            Harness.Require(!service.IsInvalid); return service;
        }
        internal static ServiceHandle OpenOwnedService(ServiceHandle manager) { var service = OpenServiceW(manager, Harness.ServiceName, 0xF01FF); Harness.Require(!service.IsInvalid); return service; }
        internal static void Configure(ServiceHandle service)
        {
            IntPtr value = Marshal.AllocHGlobal(IntPtr.Size); IntPtr privileges = Marshal.StringToHGlobalUni(string.Join("\0", Harness.Privileges) + "\0\0");
            try { Marshal.WriteInt32(value, 3); Harness.Require(ChangeServiceConfig2W(service, 5, value)); Marshal.WriteIntPtr(value, privileges); Harness.Require(ChangeServiceConfig2W(service, 6, value)); }
            finally { Marshal.FreeHGlobal(privileges); Marshal.FreeHGlobal(value); }
        }
        private static string BoundedString(IntPtr pointer, IntPtr buffer, int bytes)
        {
            long offset = pointer.ToInt64() - buffer.ToInt64(); Harness.Require(offset >= 0 && offset + 2 <= bytes && offset % 2 == 0);
            var text = new StringBuilder();
            for (long at = offset; at + 2 <= bytes; at += 2) { char unit = (char)Marshal.ReadInt16(buffer, (int)at); if (unit == 0) return text.ToString(); text.Append(unit); }
            throw new InvalidOperationException("SERVICE_PROBE_BOUNDED_QUERY_FAILED");
        }
        private static bool OptionalStringIsEmpty(IntPtr pointer, IntPtr buffer, int bytes)
        {
            return pointer == IntPtr.Zero || BoundedString(pointer, buffer, bytes) == "";
        }
        internal static void VerifyService(ServiceHandle service, string destination)
        {
            const int capacity = 8192; IntPtr buffer = Marshal.AllocHGlobal(capacity);
            try
            {
                uint needed; Harness.Require(QueryServiceConfigW(service, buffer, capacity, out needed));
                var config = (ServiceConfig)Marshal.PtrToStructure(buffer, typeof(ServiceConfig));
                Harness.Require(config.Type == 0x10 && config.Start == 3 && config.Error == 1 && config.Tag == 0 &&
                    BoundedString(config.Binary, buffer, capacity) == "\"" + Path.Combine(destination, "key-agent-service.exe") + "\"" &&
                    BoundedString(config.Account, buffer, capacity) == "NT SERVICE\\" + Harness.ServiceName &&
                    BoundedString(config.Display, buffer, capacity) == Harness.ServiceName &&
                    OptionalStringIsEmpty(config.Group, buffer, capacity) && OptionalStringIsEmpty(config.Dependencies, buffer, capacity));
                Harness.Require(QueryServiceConfig2W(service, 5, buffer, capacity, out needed) && Marshal.ReadInt32(buffer) == 3);
                Harness.Require(QueryServiceConfig2W(service, 6, buffer, capacity, out needed));
                IntPtr cursor = Marshal.ReadIntPtr(buffer); var names = new List<string>();
                for (int i = 0; i <= 4; i++) { string name = BoundedString(cursor, buffer, capacity); if (name.Length == 0) break; names.Add(name); cursor = IntPtr.Add(cursor, (name.Length + 1) * 2); }
                Harness.Require(names.SequenceEqual(Harness.Privileges));
                VerifyExactSecurity(service.DangerousGetHandle(), 2, Harness.ServiceSddl);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        internal static uint Status(ServiceHandle service)
        {
            ServiceStatus status; uint needed; Harness.Require(QueryServiceStatusEx(service, 0, out status, (uint)Marshal.SizeOf(typeof(ServiceStatus)), out needed));
            Harness.Require(status.Type == 0x10); return status.State;
        }
        private static void Wait(ServiceHandle service, uint expected)
        {
            var clock = Stopwatch.StartNew();
            while (clock.ElapsedMilliseconds < 35000) { uint state = Status(service); if (state == expected) return; Harness.Require(state == 2 || state == 3 || state == 4); System.Threading.Thread.Sleep(100); }
            throw new InvalidOperationException("SERVICE_PROBE_WAIT_EXPIRED");
        }
        internal static void Start(ServiceHandle service) { Harness.Require(Status(service) == 1 && StartServiceW(service, 0, IntPtr.Zero)); Wait(service, 4); }
        internal static void Stop(ServiceHandle service) { uint state = Status(service); if (state == 1) return; Harness.Require(state == 4); ServiceStatus status; Harness.Require(ControlService(service, 1, out status)); Wait(service, 1); }
        internal static void Delete(ServiceHandle service) { Harness.Require(Status(service) == 1 && DeleteService(service)); }
        private static SafeFileHandle OpenForDeletion(string path, bool directory)
        {
            var security = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)) };
            var file = CreateFileW(path, 0x80030000, 3, ref security, 3, 0x00200000 | (directory ? 0x02000000U : 0U), IntPtr.Zero);
            Harness.Require(!file.IsInvalid);
            FileInfo info;
            if (!GetFileInformationByHandle(file, out info) || (info.Attributes & 0x400) != 0 || (((info.Attributes & 0x10) != 0) != directory) || (!directory && info.Links != 1))
            { file.Dispose(); throw new InvalidOperationException("SERVICE_PROBE_DELETE_IDENTITY_FAILED"); }
            try { RequireNoUnprivilegedWrite(file.DangerousGetHandle()); return file; }
            catch { file.Dispose(); throw; }
        }
        internal static void DeleteExactFile(string path)
        {
            using (var file = OpenForDeletion(path, false))
            {
                byte delete = 1;
                Harness.Require(SetFileInformationByHandle(file, 4, ref delete, 1));
            }
        }
        internal static void RemoveExactDirectory(string path, string expectedIdentity)
        {
            using (var held = OpenForDeletion(path, true))
            {
                Harness.Require(Identity(held) == expectedIdentity && Directory.GetFileSystemEntries(path).Length == 0);
                byte delete = 1;
                Harness.Require(SetFileInformationByHandle(held, 4, ref delete, 1));
            }
        }

        private static byte[] SidBytes(string sid) { var value = new SecurityIdentifier(sid); byte[] bytes = new byte[value.BinaryLength]; value.GetBinaryForm(bytes, 0); return bytes; }
        private static IntPtr Policy(bool create)
        {
            var attributes = new LsaAttributes { Length = (uint)Marshal.SizeOf(typeof(LsaAttributes)) }; IntPtr policy;
            Harness.Require(LsaOpenPolicy(IntPtr.Zero, ref attributes, create ? 0x810U : 0x800U, out policy) == 0 && policy != IntPtr.Zero); return policy;
        }
        internal static string[] ReadRights(string sid)
        {
            IntPtr policy = Policy(false); IntPtr rights = IntPtr.Zero;
            try
            {
                uint count; uint status = LsaEnumerateAccountRights(policy, SidBytes(sid), out rights, out count);
                if (status != 0 && LsaNtStatusToWinError(status) == 2) return new string[0];
                Harness.Require(status == 0 && count <= 64); var result = new List<string>();
                for (int i = 0; i < count; i++) { var value = (LsaString)Marshal.PtrToStructure(IntPtr.Add(rights, i * Marshal.SizeOf(typeof(LsaString))), typeof(LsaString)); Harness.Require(value.Length > 0 && value.Length <= 128 && value.Length % 2 == 0 && value.Length <= value.MaximumLength); result.Add(Marshal.PtrToStringUni(value.Buffer, value.Length / 2)); }
                Harness.Require(result.Distinct(StringComparer.Ordinal).Count() == result.Count); return result.OrderBy(x => x, StringComparer.Ordinal).ToArray();
            }
            finally { if (rights != IntPtr.Zero) CheckCleanup(LsaFreeMemory(rights) == 0); CheckCleanup(LsaClose(policy) == 0); }
        }
        private static void ChangeRights(string sid, string[] names, bool add)
        {
            if (names.Length == 0) return;
            Harness.Require(sid == ServiceSid() && names.All(x => Harness.Rights.Contains(x, StringComparer.Ordinal)) && names.Distinct().Count() == names.Length);
            IntPtr policy = Policy(add); var rights = new LsaString[names.Length];
            try
            {
                for (int i = 0; i < names.Length; i++) rights[i] = new LsaString { Length = checked((ushort)(names[i].Length * 2)), MaximumLength = checked((ushort)((names[i].Length + 1) * 2)), Buffer = Marshal.StringToHGlobalUni(names[i]) };
                uint result = add ? LsaAddAccountRights(policy, SidBytes(sid), rights, (uint)rights.Length) : LsaRemoveAccountRights(policy, SidBytes(sid), false, rights, (uint)rights.Length);
                Harness.Require(result == 0);
            }
            finally { foreach (var right in rights) if (right.Buffer != IntPtr.Zero) Marshal.FreeHGlobal(right.Buffer); CheckCleanup(LsaClose(policy) == 0); }
        }
        internal static void AddRights(string sid, string[] names) { ChangeRights(sid, names, true); }
        internal static void RemoveRights(string sid, string[] names) { ChangeRights(sid, names, false); }
    }
}
