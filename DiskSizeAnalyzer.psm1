<#
.SYNOPSIS
    Fast disk space analyzer module using MFT (Master File Table) reading.

.DESCRIPTION
    This module provides the Get-DiskSpaceUsage function that reads the NTFS MFT directly
    to quickly enumerate all files and directories, calculates sizes, and returns the
    largest items as PowerShell objects.

.NOTES
    Requires Administrator privileges for raw disk access.
    For remote computers, requires PowerShell Remoting to be enabled.
#>

#region C# Code for MFT Reading

$script:CSharpCode = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

public class MftReader
{
    #region Win32 API

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064;

    #endregion

    #region NTFS Structures

    [StructLayout(LayoutKind.Sequential)]
    private struct NTFS_VOLUME_DATA_BUFFER
    {
        public long VolumeSerialNumber;
        public long NumberSectors;
        public long TotalClusters;
        public long FreeClusters;
        public long TotalReserved;
        public uint BytesPerSector;
        public uint BytesPerCluster;
        public uint BytesPerFileRecordSegment;
        public uint ClustersPerFileRecordSegment;
        public long MftValidDataLength;
        public long MftStartLcn;
        public long Mft2StartLcn;
        public long MftZoneStart;
        public long MftZoneEnd;
    }

    #endregion

    public class FileRecord
    {
        public ulong RecordNumber;
        public ulong ParentRecordNumber;
        public string FileName;
        public long FileSize;
        public long AllocatedSize;
        public bool IsDirectory;
        public bool IsDeleted;
        public bool IsValid;
    }

    public class FileItem
    {
        public string FullPath;
        public long Size;
        public bool IsDirectory;
    }

    private string _driveLetter;
    private Dictionary<ulong, FileRecord> _records;
    private Dictionary<ulong, long> _directorySizes;
    private Dictionary<ulong, string> _pathCache;

    public MftReader(string driveLetter)
    {
        _driveLetter = driveLetter.ToUpper();
        _records = new Dictionary<ulong, FileRecord>();
        _directorySizes = new Dictionary<ulong, long>();
        _pathCache = new Dictionary<ulong, string>();
    }

    public void ReadMft(Action<int> progressCallback = null)
    {
        string volumePath = @"\\.\" + _driveLetter + ":";

        using (SafeFileHandle volumeHandle = CreateFile(
            volumePath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero))
        {
            if (volumeHandle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open volume");

            // Get NTFS volume data
            NTFS_VOLUME_DATA_BUFFER volumeData = new NTFS_VOLUME_DATA_BUFFER();
            IntPtr volumeDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf(volumeData));

            try
            {
                uint bytesReturned;
                if (!DeviceIoControl(volumeHandle, FSCTL_GET_NTFS_VOLUME_DATA,
                    IntPtr.Zero, 0, volumeDataPtr, (uint)Marshal.SizeOf(volumeData),
                    out bytesReturned, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to get volume data");
                }

                volumeData = (NTFS_VOLUME_DATA_BUFFER)Marshal.PtrToStructure(
                    volumeDataPtr, typeof(NTFS_VOLUME_DATA_BUFFER));
            }
            finally
            {
                Marshal.FreeHGlobal(volumeDataPtr);
            }

            long mftStart = volumeData.MftStartLcn * volumeData.BytesPerCluster;
            int recordSize = (int)volumeData.BytesPerFileRecordSegment;
            long mftSize = volumeData.MftValidDataLength;
            long totalRecords = mftSize / recordSize;

            byte[] recordBuffer = new byte[recordSize];
            long currentOffset = mftStart;
            ulong recordNumber = 0;
            int lastProgress = -1;

            while (currentOffset < mftStart + mftSize)
            {
                long newPointer;
                if (!SetFilePointerEx(volumeHandle, currentOffset, out newPointer, 0))
                    break;

                uint bytesRead;
                if (!ReadFile(volumeHandle, recordBuffer, (uint)recordSize, out bytesRead, IntPtr.Zero))
                    break;

                if (bytesRead < recordSize)
                    break;

                FileRecord record = ParseMftRecord(recordBuffer, recordNumber);
                if (record != null && record.IsValid && !record.IsDeleted)
                {
                    _records[recordNumber] = record;
                }

                recordNumber++;
                currentOffset += recordSize;

                // Progress callback every 1%
                if (progressCallback != null)
                {
                    int progress = (int)((recordNumber * 100) / (ulong)totalRecords);
                    if (progress != lastProgress)
                    {
                        lastProgress = progress;
                        progressCallback(progress);
                    }
                }
            }
        }
    }

    private FileRecord ParseMftRecord(byte[] buffer, ulong recordNumber)
    {
        FileRecord record = new FileRecord();
        record.RecordNumber = recordNumber;
        record.IsValid = false;

        // Check FILE signature
        if (buffer[0] != 'F' || buffer[1] != 'I' || buffer[2] != 'L' || buffer[3] != 'E')
            return record;

        // Get flags
        ushort flags = BitConverter.ToUInt16(buffer, 22);
        record.IsDeleted = (flags & 0x01) == 0;
        record.IsDirectory = (flags & 0x02) != 0;

        // Get first attribute offset
        ushort attrOffset = BitConverter.ToUInt16(buffer, 20);

        // Parse attributes
        while (attrOffset < buffer.Length - 8)
        {
            uint attrType = BitConverter.ToUInt32(buffer, attrOffset);

            // End of attributes
            if (attrType == 0xFFFFFFFF || attrType == 0)
                break;

            uint attrLength = BitConverter.ToUInt32(buffer, attrOffset + 4);
            if (attrLength == 0 || attrLength > buffer.Length - attrOffset)
                break;

            // $FILE_NAME attribute (0x30)
            if (attrType == 0x30)
            {
                byte nonResident = buffer[attrOffset + 8];
                if (nonResident == 0) // Resident
                {
                    ushort contentOffset = BitConverter.ToUInt16(buffer, attrOffset + 20);
                    int fnOffset = attrOffset + contentOffset;

                    if (fnOffset + 66 < buffer.Length)
                    {
                        // Parent directory reference (6 bytes) + sequence (2 bytes)
                        ulong parentRef = BitConverter.ToUInt64(buffer, fnOffset) & 0x0000FFFFFFFFFFFF;
                        record.ParentRecordNumber = parentRef;

                        // Allocated size and real size from $FILE_NAME
                        record.AllocatedSize = BitConverter.ToInt64(buffer, fnOffset + 40);
                        long fnFileSize = BitConverter.ToInt64(buffer, fnOffset + 48);

                        // Filename length and namespace
                        byte nameLength = buffer[fnOffset + 64];
                        byte nameSpace = buffer[fnOffset + 65];

                        // Skip DOS names (namespace 2), prefer Win32 or POSIX
                        if (nameSpace != 2 && fnOffset + 66 + nameLength * 2 <= buffer.Length)
                        {
                            try
                            {
                                record.FileName = System.Text.Encoding.Unicode.GetString(
                                    buffer, fnOffset + 66, nameLength * 2);
                            }
                            catch { }
                        }
                        else if (string.IsNullOrEmpty(record.FileName) && fnOffset + 66 + nameLength * 2 <= buffer.Length)
                        {
                            try
                            {
                                record.FileName = System.Text.Encoding.Unicode.GetString(
                                    buffer, fnOffset + 66, nameLength * 2);
                            }
                            catch { }
                        }
                    }
                }
            }
            // $DATA attribute (0x80)
            else if (attrType == 0x80)
            {
                byte nonResident = buffer[attrOffset + 8];

                // Only process unnamed $DATA attribute (main file data)
                byte nameLen = buffer[attrOffset + 9];
                if (nameLen == 0)
                {
                    if (nonResident == 0) // Resident
                    {
                        uint contentSize = BitConverter.ToUInt32(buffer, attrOffset + 16);
                        record.FileSize = contentSize;
                    }
                    else // Non-resident
                    {
                        if (attrOffset + 48 <= buffer.Length)
                        {
                            record.FileSize = BitConverter.ToInt64(buffer, attrOffset + 48);
                        }
                    }
                }
            }

            attrOffset += (ushort)attrLength;
        }

        record.IsValid = !string.IsNullOrEmpty(record.FileName);
        return record;
    }

    public string GetFullPath(ulong recordNumber)
    {
        if (_pathCache.ContainsKey(recordNumber))
            return _pathCache[recordNumber];

        List<string> parts = new List<string>();
        ulong current = recordNumber;
        int maxDepth = 100; // Prevent infinite loops

        while (maxDepth-- > 0)
        {
            if (!_records.ContainsKey(current))
                break;

            FileRecord record = _records[current];

            // Root directory (record 5)
            if (current == 5 || record.ParentRecordNumber == current)
            {
                parts.Insert(0, _driveLetter + ":");
                break;
            }

            parts.Insert(0, record.FileName);
            current = record.ParentRecordNumber;
        }

        string path = string.Join(@"\", parts);
        _pathCache[recordNumber] = path;
        return path;
    }

    public void CalculateDirectorySizes()
    {
        // First pass: add file sizes to their parent directories
        foreach (var kvp in _records)
        {
            FileRecord record = kvp.Value;
            if (!record.IsDirectory && record.FileSize > 0)
            {
                ulong parentId = record.ParentRecordNumber;
                if (!_directorySizes.ContainsKey(parentId))
                    _directorySizes[parentId] = 0;
                _directorySizes[parentId] += record.FileSize;
            }
        }

        // Build directory tree relationships
        Dictionary<ulong, List<ulong>> children = new Dictionary<ulong, List<ulong>>();
        foreach (var kvp in _records)
        {
            if (kvp.Value.IsDirectory)
            {
                ulong parentId = kvp.Value.ParentRecordNumber;
                if (!children.ContainsKey(parentId))
                    children[parentId] = new List<ulong>();
                children[parentId].Add(kvp.Key);
            }
        }

        // Recursive calculation - use iterative approach to avoid stack overflow
        HashSet<ulong> calculated = new HashSet<ulong>();
        Stack<ulong> toProcess = new Stack<ulong>();

        // Start from all directories
        foreach (var kvp in _records)
        {
            if (kvp.Value.IsDirectory)
                toProcess.Push(kvp.Key);
        }

        // Multiple passes to propagate sizes up
        for (int pass = 0; pass < 50; pass++)
        {
            bool changed = false;
            foreach (var kvp in _records)
            {
                if (!kvp.Value.IsDirectory) continue;

                ulong dirId = kvp.Key;
                if (children.ContainsKey(dirId))
                {
                    foreach (ulong childId in children[dirId])
                    {
                        if (_directorySizes.ContainsKey(childId))
                        {
                            if (!_directorySizes.ContainsKey(dirId))
                                _directorySizes[dirId] = 0;

                            // This is a simplification - in reality we'd need proper tree traversal
                        }
                    }
                }
            }

            // Propagate child directory sizes to parents
            foreach (var kvp in _records)
            {
                if (!kvp.Value.IsDirectory) continue;

                ulong parentId = kvp.Value.ParentRecordNumber;
                if (parentId != kvp.Key && _directorySizes.ContainsKey(kvp.Key))
                {
                    long childSize = _directorySizes[kvp.Key];
                    if (!_directorySizes.ContainsKey(parentId))
                        _directorySizes[parentId] = 0;

                    // Only add once per pass if not already included
                }
            }

            if (!changed) break;
        }
    }

    public List<FileItem> GetLargestDirectories(int count)
    {
        const long MAX_VALID_SIZE = 20L * 1024 * 1024 * 1024 * 1024; // 20 TB sanity limit
        
        // Step 1: Sum direct file sizes per parent directory
        Dictionary<ulong, long> directFileSizes = new Dictionary<ulong, long>();
        
        foreach (var kvp in _records)
        {
            FileRecord rec = kvp.Value;
            // Only count files with valid positive sizes within sanity limit
            if (!rec.IsDirectory && rec.FileSize > 0 && rec.FileSize < MAX_VALID_SIZE)
            {
                ulong parentId = rec.ParentRecordNumber;
                // Validate parent exists
                if (_records.ContainsKey(parentId))
                {
                    if (!directFileSizes.ContainsKey(parentId))
                        directFileSizes[parentId] = 0;
                    directFileSizes[parentId] += rec.FileSize;
                }
            }
        }

        // Step 2: Build child directory map
        Dictionary<ulong, List<ulong>> childDirs = new Dictionary<ulong, List<ulong>>();
        foreach (var kvp in _records)
        {
            FileRecord rec = kvp.Value;
            if (rec.IsDirectory && rec.ParentRecordNumber != kvp.Key)
            {
                ulong parentId = rec.ParentRecordNumber;
                if (_records.ContainsKey(parentId))
                {
                    if (!childDirs.ContainsKey(parentId))
                        childDirs[parentId] = new List<ulong>();
                    childDirs[parentId].Add(kvp.Key);
                }
            }
        }

        // Step 3: Calculate cumulative sizes bottom-up (leaves first)
        Dictionary<ulong, long> cumulativeSizes = new Dictionary<ulong, long>();
        HashSet<ulong> processed = new HashSet<ulong>();
        
        // Find leaf directories first (directories with no child directories)
        Queue<ulong> toProcess = new Queue<ulong>();
        Dictionary<ulong, int> pendingChildren = new Dictionary<ulong, int>();
        
        foreach (var kvp in _records)
        {
            if (!kvp.Value.IsDirectory) continue;
            ulong dirId = kvp.Key;
            int childCount = childDirs.ContainsKey(dirId) ? childDirs[dirId].Count : 0;
            pendingChildren[dirId] = childCount;
            if (childCount == 0)
                toProcess.Enqueue(dirId);
        }
        
        // Process from leaves up
        while (toProcess.Count > 0)
        {
            ulong dirId = toProcess.Dequeue();
            if (processed.Contains(dirId)) continue;
            processed.Add(dirId);
            
            long size = directFileSizes.ContainsKey(dirId) ? directFileSizes[dirId] : 0;
            
            // Add sizes of child directories
            if (childDirs.ContainsKey(dirId))
            {
                foreach (ulong childId in childDirs[dirId])
                {
                    if (cumulativeSizes.ContainsKey(childId))
                        size += cumulativeSizes[childId];
                }
            }
            
            cumulativeSizes[dirId] = size;
            
            // Notify parent
            if (_records.ContainsKey(dirId))
            {
                ulong parentId = _records[dirId].ParentRecordNumber;
                if (parentId != dirId && pendingChildren.ContainsKey(parentId))
                {
                    pendingChildren[parentId]--;
                    if (pendingChildren[parentId] <= 0 && !processed.Contains(parentId))
                        toProcess.Enqueue(parentId);
                }
            }
        }

        // Step 4: Sort and filter results
        List<KeyValuePair<ulong, long>> sorted = new List<KeyValuePair<ulong, long>>(cumulativeSizes);
        sorted.Sort((a, b) => b.Value.CompareTo(a.Value));

        List<FileItem> results = new List<FileItem>();
        int added = 0;
        
        foreach (var kvp in sorted)
        {
            if (added >= count) break;
            if (kvp.Value <= 0) continue;
            if (!_records.ContainsKey(kvp.Key)) continue;

            string path = GetFullPath(kvp.Key);
            if (string.IsNullOrEmpty(path)) continue;
            if (!path.Contains(":")) continue;  // Must have drive letter (valid path)
            if (path.Contains("$")) continue;   // Skip system files

            results.Add(new FileItem
            {
                FullPath = path,
                Size = kvp.Value,
                IsDirectory = true
            });
            added++;
        }

        return results;
    }

    public List<FileItem> GetLargestFiles(int count)
    {
        const long MAX_VALID_SIZE = 20L * 1024 * 1024 * 1024 * 1024; // 20 TB sanity limit
        List<KeyValuePair<ulong, FileRecord>> files = new List<KeyValuePair<ulong, FileRecord>>();

        foreach (var kvp in _records)
        {
            if (!kvp.Value.IsDirectory && kvp.Value.FileSize > 0 && kvp.Value.FileSize < MAX_VALID_SIZE)
            {
                files.Add(kvp);
            }
        }

        files.Sort((a, b) => b.Value.FileSize.CompareTo(a.Value.FileSize));

        List<FileItem> results = new List<FileItem>();
        int added = 0;

        foreach (var kvp in files)
        {
            if (added >= count) break;

            string path = GetFullPath(kvp.Key);
            if (string.IsNullOrEmpty(path)) continue;
            if (!path.Contains(":")) continue;  // Must have drive letter
            if (path.Contains("$")) continue;

            results.Add(new FileItem
            {
                FullPath = path,
                Size = kvp.Value.FileSize,
                IsDirectory = false
            });
            added++;
        }

        return results;
    }

    public int RecordCount { get { return _records.Count; } }
}
'@

#endregion

#region Helper Functions

function Format-FileSize {
    <#
    .SYNOPSIS
        Formats a byte size into a human-readable string.
    #>
    param([long]$Bytes)
    
    if ($Bytes -ge 1TB) { return "{0:F2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:F2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:F2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:F2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Initialize-MftReaderType {
    <#
    .SYNOPSIS
        Ensures the MftReader C# type is loaded.
    #>
    if (-not ([System.Management.Automation.PSTypeName]'MftReader').Type) {
        Add-Type -TypeDefinition $script:CSharpCode -Language CSharp -ErrorAction Stop
    }
}

#endregion

#region Main Function

function Get-DiskSpaceUsage {
    <#
    .SYNOPSIS
        Fast disk space analyzer using MFT (Master File Table) reading.

    .DESCRIPTION
        Reads the NTFS MFT directly to quickly enumerate all files and directories,
        then calculates sizes and returns the largest items as PowerShell objects.
        
        Supports analyzing local or remote computers. For remote computers, PowerShell
        Remoting must be enabled on the target machine.

    .PARAMETER DriveLetter
        The drive letter to scan (e.g., "C"). Default is "C".

    .PARAMETER TopCount
        Number of top results to return (default: 30).

    .PARAMETER IncludeFiles
        Also include largest individual files in the output (not just directories).

    .PARAMETER ComputerName
        One or more computer names to analyze. If not specified, analyzes the local computer.
        Requires PowerShell Remoting to be enabled on remote computers.

    .PARAMETER Credential
        Credentials to use for remote computer connections. If not specified, uses current user credentials.

    .EXAMPLE
        Get-DiskSpaceUsage
        
        Analyzes the C: drive on the local computer and returns the 30 largest directories.

    .EXAMPLE
        Get-DiskSpaceUsage -DriveLetter D -TopCount 50
        
        Analyzes the D: drive and returns the 50 largest directories.

    .EXAMPLE
        Get-DiskSpaceUsage -IncludeFiles | Export-Csv -Path "DiskUsage.csv" -NoTypeInformation
        
        Exports the disk usage analysis including files to a CSV file.

    .EXAMPLE
        Get-DiskSpaceUsage -ComputerName "Server01", "Server02" -Credential (Get-Credential)
        
        Analyzes the C: drive on Server01 and Server02 using specified credentials.

    .EXAMPLE
        "Server01", "Server02" | Get-DiskSpaceUsage -DriveLetter D
        
        Analyzes the D: drive on multiple servers via pipeline input.

    .EXAMPLE
        Get-DiskSpaceUsage -ComputerName "Server01" | Where-Object { $_.SizeGB -gt 10 }
        
        Gets directories larger than 10 GB from a remote server.

    .OUTPUTS
        PSCustomObject with properties:
        - ComputerName: The computer where the item is located
        - Rank: The ranking by size (1 = largest)
        - Path: Full path to the directory or file
        - Size: Size in bytes
        - SizeFormatted: Human-readable size string
        - SizeKB: Size in kilobytes
        - SizeMB: Size in megabytes
        - SizeGB: Size in gigabytes
        - Type: "Directory" or "File"
        - ScanDate: When the scan was performed

    .NOTES
        Requires Administrator privileges for raw disk access.
        For remote computers, requires PowerShell Remoting to be enabled.
        Only works with NTFS formatted drives.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidatePattern('^[A-Za-z]$')]
        [string]$DriveLetter = 'C',

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$TopCount = 30,

        [Parameter()]
        [switch]$IncludeFiles,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CN', 'Server', 'PSComputerName')]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    begin {
        # Script block to run on each computer (local or remote)
        $analysisScriptBlock = {
            param(
                [string]$DriveLetter,
                [int]$TopCount,
                [bool]$IncludeFiles,
                [string]$CSharpCode
            )

            # Require admin for local execution check
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                throw "Administrator privileges required for raw disk access. Please run as Administrator."
            }

            # Add the C# type if not already loaded
            if (-not ([System.Management.Automation.PSTypeName]'MftReader').Type) {
                Add-Type -TypeDefinition $CSharpCode -Language CSharp -ErrorAction Stop
            }

            # Create reader and perform analysis
            $reader = New-Object MftReader($DriveLetter)
            $reader.ReadMft($null)
            $reader.CalculateDirectorySizes()

            $results = @()
            $scanDate = Get-Date
            $computerName = $env:COMPUTERNAME

            # Get largest directories
            $dirs = $reader.GetLargestDirectories($TopCount)
            $rank = 1
            foreach ($dir in $dirs) {
                $results += [PSCustomObject]@{
                    ComputerName  = $computerName
                    Rank          = $rank
                    Path          = $dir.FullPath
                    Size          = $dir.Size
                    SizeFormatted = if ($dir.Size -ge 1TB) { "{0:F2} TB" -f ($dir.Size / 1TB) }
                                   elseif ($dir.Size -ge 1GB) { "{0:F2} GB" -f ($dir.Size / 1GB) }
                                   elseif ($dir.Size -ge 1MB) { "{0:F2} MB" -f ($dir.Size / 1MB) }
                                   elseif ($dir.Size -ge 1KB) { "{0:F2} KB" -f ($dir.Size / 1KB) }
                                   else { "$($dir.Size) B" }
                    SizeKB        = [math]::Round($dir.Size / 1KB, 2)
                    SizeMB        = [math]::Round($dir.Size / 1MB, 2)
                    SizeGB        = [math]::Round($dir.Size / 1GB, 2)
                    Type          = 'Directory'
                    ScanDate      = $scanDate
                }
                $rank++
            }

            # Get largest files if requested
            if ($IncludeFiles) {
                $files = $reader.GetLargestFiles($TopCount)
                $rank = 1
                foreach ($file in $files) {
                    $results += [PSCustomObject]@{
                        ComputerName  = $computerName
                        Rank          = $rank
                        Path          = $file.FullPath
                        Size          = $file.Size
                        SizeFormatted = if ($file.Size -ge 1TB) { "{0:F2} TB" -f ($file.Size / 1TB) }
                                       elseif ($file.Size -ge 1GB) { "{0:F2} GB" -f ($file.Size / 1GB) }
                                       elseif ($file.Size -ge 1MB) { "{0:F2} MB" -f ($file.Size / 1MB) }
                                       elseif ($file.Size -ge 1KB) { "{0:F2} KB" -f ($file.Size / 1KB) }
                                       else { "$($file.Size) B" }
                        SizeKB        = [math]::Round($file.Size / 1KB, 2)
                        SizeMB        = [math]::Round($file.Size / 1MB, 2)
                        SizeGB        = [math]::Round($file.Size / 1GB, 2)
                        Type          = 'File'
                        ScanDate      = $scanDate
                    }
                    $rank++
                }
            }

            return $results
        }

        # Collect all computer names from pipeline
        $allComputers = [System.Collections.Generic.List[string]]::new()
    }

    process {
        if ($ComputerName) {
            foreach ($computer in $ComputerName) {
                $allComputers.Add($computer)
            }
        }
    }

    end {
        # If no computers specified, run locally
        if ($allComputers.Count -eq 0) {
            Write-Verbose "Analyzing local computer drive $($DriveLetter):\"
            
            # Check admin privileges locally
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                throw "Administrator privileges required for raw disk access. Please run as Administrator."
            }

            try {
                Initialize-MftReaderType
                
                $reader = New-Object MftReader($DriveLetter)
                
                Write-Verbose "Reading MFT from drive $($DriveLetter):\..."
                $reader.ReadMft($null)
                
                Write-Verbose "MFT read complete: $($reader.RecordCount.ToString('N0')) records"
                Write-Verbose "Calculating directory sizes..."
                $reader.CalculateDirectorySizes()
                
                $scanDate = Get-Date
                $computerName = $env:COMPUTERNAME

                # Get largest directories
                $dirs = $reader.GetLargestDirectories($TopCount)
                $rank = 1
                foreach ($dir in $dirs) {
                    [PSCustomObject]@{
                        ComputerName  = $computerName
                        Rank          = $rank
                        Path          = $dir.FullPath
                        Size          = $dir.Size
                        SizeFormatted = Format-FileSize $dir.Size
                        SizeKB        = [math]::Round($dir.Size / 1KB, 2)
                        SizeMB        = [math]::Round($dir.Size / 1MB, 2)
                        SizeGB        = [math]::Round($dir.Size / 1GB, 2)
                        Type          = 'Directory'
                        ScanDate      = $scanDate
                    }
                    $rank++
                }

                # Get largest files if requested
                if ($IncludeFiles) {
                    $files = $reader.GetLargestFiles($TopCount)
                    $rank = 1
                    foreach ($file in $files) {
                        [PSCustomObject]@{
                            ComputerName  = $computerName
                            Rank          = $rank
                            Path          = $file.FullPath
                            Size          = $file.Size
                            SizeFormatted = Format-FileSize $file.Size
                            SizeKB        = [math]::Round($file.Size / 1KB, 2)
                            SizeMB        = [math]::Round($file.Size / 1MB, 2)
                            SizeGB        = [math]::Round($file.Size / 1GB, 2)
                            Type          = 'File'
                            ScanDate      = $scanDate
                        }
                        $rank++
                    }
                }
            }
            catch {
                Write-Error "Error analyzing local computer: $_"
            }
        }
        else {
            # Run on remote computers
            foreach ($computer in $allComputers) {
                Write-Verbose "Analyzing $computer drive $($DriveLetter):\"
                
                try {
                    $invokeParams = @{
                        ComputerName = $computer
                        ScriptBlock  = $analysisScriptBlock
                        ArgumentList = @($DriveLetter, $TopCount, $IncludeFiles.IsPresent, $script:CSharpCode)
                        ErrorAction  = 'Stop'
                    }

                    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
                        $invokeParams['Credential'] = $Credential
                    }

                    $results = Invoke-Command @invokeParams

                    # Output results (remove PSComputerName added by Invoke-Command, we have our own)
                    foreach ($result in $results) {
                        [PSCustomObject]@{
                            ComputerName  = $result.ComputerName
                            Rank          = $result.Rank
                            Path          = $result.Path
                            Size          = $result.Size
                            SizeFormatted = $result.SizeFormatted
                            SizeKB        = $result.SizeKB
                            SizeMB        = $result.SizeMB
                            SizeGB        = $result.SizeGB
                            Type          = $result.Type
                            ScanDate      = $result.ScanDate
                        }
                    }
                }
                catch {
                    Write-Error "Error analyzing $computer`: $_"
                }
            }
        }
    }
}

#endregion

# Export the function
Export-ModuleMember -Function Get-DiskSpaceUsage
