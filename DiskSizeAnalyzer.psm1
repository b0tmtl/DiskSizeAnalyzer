<#
.SYNOPSIS
    Fast disk space analyzer module using MFT (Master File Table) reading.
.NOTES
    Requires Administrator privileges for raw disk access.
#>

$script:CSharpCode = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

public class MftReader
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile, long liDistanceToMove,
        out long lpNewFilePointer, uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile, byte[] lpBuffer,
        uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
    private const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064;

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

    public struct FileRecord
    {
        public ulong ParentRecordNumber;
        public string FileName;
        public long FileSize;
        public long AllocatedSize;
        public ushort Flags;
        public bool IsDirectory { get { return (Flags & 0x02) != 0; } }
        public bool IsDeleted { get { return (Flags & 0x01) == 0; } }
        public bool IsValid { get { return FileName != null; } }
    }

    public class FileItem
    {
        public string FullPath;
        public long Size;
        public bool IsDirectory;
    }

    private string _driveLetter;
    private Dictionary<ulong, FileRecord> _records;
    private Dictionary<ulong, string> _pathCache;
    private long _totalRecordsScanned;

    public long IoTimeMs;
    public long ParseTimeMs;
    public long TotalTimeMs;

    public MftReader(string driveLetter)
    {
        _driveLetter = driveLetter.ToUpper();
        _records = new Dictionary<ulong, FileRecord>();
        _pathCache = new Dictionary<ulong, string>();
    }

    private struct MftExtent
    {
        public long StartLcn;
        public long ClusterCount;
    }

    private NTFS_VOLUME_DATA_BUFFER GetVolumeData(SafeFileHandle volumeHandle)
    {
        NTFS_VOLUME_DATA_BUFFER volumeData = new NTFS_VOLUME_DATA_BUFFER();
        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(volumeData));
        try
        {
            uint bytesReturned;
            if (!DeviceIoControl(volumeHandle, FSCTL_GET_NTFS_VOLUME_DATA,
                IntPtr.Zero, 0, ptr, (uint)Marshal.SizeOf(volumeData),
                out bytesReturned, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to get volume data");
            return (NTFS_VOLUME_DATA_BUFFER)Marshal.PtrToStructure(ptr, typeof(NTFS_VOLUME_DATA_BUFFER));
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public void ReadMft(Action<int> progressCallback = null)
    {
        Stopwatch totalSw = Stopwatch.StartNew();
        Stopwatch ioSw = new Stopwatch();
        Stopwatch parseSw = new Stopwatch();

        string volumePath = @"\\.\" + _driveLetter + ":";

        using (SafeFileHandle volumeHandle = CreateFile(
            volumePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero))
        {
            if (volumeHandle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open volume");

            NTFS_VOLUME_DATA_BUFFER volumeData = GetVolumeData(volumeHandle);

            int recordSize = (int)volumeData.BytesPerFileRecordSegment;
            int clusterSize = (int)volumeData.BytesPerCluster;
            long mftSize = volumeData.MftValidDataLength;
            long totalRecords = mftSize / recordSize;
            long mftStartByte = volumeData.MftStartLcn * clusterSize;

            _totalRecordsScanned = totalRecords;
            int estimatedRecords = (int)Math.Min(totalRecords * 3 / 4, int.MaxValue);
            _records = new Dictionary<ulong, FileRecord>(estimatedRecords);

            // Read MFT record 0 to get data runs
            byte[] mftRecord0 = new byte[recordSize];
            long newPointer;
            uint bytesRead;

            if (!SetFilePointerEx(volumeHandle, mftStartByte, out newPointer, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to seek to MFT start");
            if (!ReadFile(volumeHandle, mftRecord0, (uint)recordSize, out bytesRead, IntPtr.Zero) || bytesRead < recordSize)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to read MFT record 0");

            List<MftExtent> mftExtents = ParseMftDataRuns(mftRecord0, volumeData.MftStartLcn);
            if (mftExtents.Count == 0)
            {
                mftExtents.Add(new MftExtent {
                    StartLcn = volumeData.MftStartLcn,
                    ClusterCount = (mftSize + clusterSize - 1) / clusterSize
                });
            }

            // 64 MB chunks for maximum throughput
            const int CHUNK_SIZE = 64 * 1024 * 1024;
            int chunkRecords = CHUNK_SIZE / recordSize;
            int chunkBytes = chunkRecords * recordSize;
            byte[] chunkBuffer = new byte[chunkBytes];

            ulong recordNumber = 0;
            int lastProgress = -1;
            int recordsPerCluster = clusterSize / recordSize;
            if (recordsPerCluster < 1) recordsPerCluster = 1;

            foreach (MftExtent extent in mftExtents)
            {
                long extentStartByte = extent.StartLcn * clusterSize;
                long extentTotalRecords = extent.ClusterCount * recordsPerCluster;
                long recordsRemaining = (long)((ulong)totalRecords - recordNumber);
                if (recordsRemaining <= 0) break;
                long recordsToRead = Math.Min(extentTotalRecords, recordsRemaining);
                long bytesToReadTotal = recordsToRead * recordSize;

                if (!SetFilePointerEx(volumeHandle, extentStartByte, out newPointer, 0))
                    break;

                long bytesRemainingInExtent = bytesToReadTotal;

                while (bytesRemainingInExtent > 0 && recordNumber < (ulong)totalRecords)
                {
                    int toRead = (int)Math.Min(chunkBytes, bytesRemainingInExtent);

                    ioSw.Start();
                    bool readOk = ReadFile(volumeHandle, chunkBuffer, (uint)toRead, out bytesRead, IntPtr.Zero);
                    ioSw.Stop();

                    if (!readOk || bytesRead == 0) break;

                    int recordsInChunk = (int)bytesRead / recordSize;

                    parseSw.Start();
                    ParseChunkUnsafe(chunkBuffer, recordsInChunk, recordSize, ref recordNumber, (ulong)totalRecords);
                    parseSw.Stop();

                    if (progressCallback != null)
                    {
                        int progress = (int)((recordNumber * 100) / (ulong)totalRecords);
                        if (progress != lastProgress) { lastProgress = progress; progressCallback(progress); }
                    }

                    bytesRemainingInExtent -= bytesRead;
                }
            }
        }

        totalSw.Stop();
        IoTimeMs = ioSw.ElapsedMilliseconds;
        ParseTimeMs = parseSw.ElapsedMilliseconds;
        TotalTimeMs = totalSw.ElapsedMilliseconds;
    }

/// <summary>
    /// Parse an entire chunk using unsafe pointers â€” eliminates ALL array bounds checking.
    /// This is the single biggest performance optimization.
    /// </summary>
    private unsafe void ParseChunkUnsafe(byte[] chunkBuffer, int recordCount, int recordSize, ref ulong recordNumber, ulong totalRecords)
    {
        fixed (byte* bufBase = chunkBuffer)
        {
            for (int i = 0; i < recordCount && recordNumber < totalRecords; i++)
            {
                byte* p = bufBase + (i * recordSize);
                byte* pEnd = p + recordSize;

                // Signature check: "FILE" = 0x454C4946 little-endian
                if (*(uint*)p != 0x454C4946) { recordNumber++; continue; }

                // Flags at offset 22
                ushort flags = *(ushort*)(p + 22);
                if ((flags & 0x01) == 0) { recordNumber++; continue; } // deleted

                // First attribute offset
                ushort firstAttrOffset = *(ushort*)(p + 20);
                byte* attr = p + firstAttrOffset;

                FileRecord rec = new FileRecord();
                rec.Flags = flags;
                bool isDir = (flags & 0x02) != 0;
                bool hasName = false;
                bool hasWin32Name = false; // [FIX] Track if we found a "Real" name
                bool hasSize = false;
                long fileNameSize = 0;

                while (attr < pEnd - 8)
                {
                    uint attrType = *(uint*)attr;
                    if (attrType == 0xFFFFFFFF || attrType == 0) break;

                    uint attrLen = *(uint*)(attr + 4);
                    if (attrLen == 0 || attr + attrLen > pEnd) break;

                    if (attrType == 0x30) // $FILE_NAME
                    {
                        if (*(attr + 8) == 0) // Resident
                        {
                            ushort contentOffset = *(ushort*)(attr + 20);
                            byte* fn = attr + contentOffset;

                            if (fn + 66 < pEnd)
                            {
                                rec.ParentRecordNumber = (*(ulong*)fn) & 0x0000FFFFFFFFFFFF;
                                rec.AllocatedSize = *(long*)(fn + 40);
                                long fnSize = *(long*)(fn + 48);
                                if (fnSize > fileNameSize) fileNameSize = fnSize;

                                byte nameLen = *(fn + 64);
                                byte nameSpace = *(fn + 65);

                                if (nameLen > 0 && fn + 66 + nameLen * 2 <= pEnd)
                                {
                                    // Namespace 2 is DOS (8.3). Namespace 1 or 3 is Win32/Long.
                                    if (nameSpace != 2) 
                                    {
                                        // [FIX] Always prefer Win32 names. Overwrite if necessary.
                                        try { rec.FileName = new string((char*)(fn + 66), 0, nameLen); hasName = true; hasWin32Name = true; }
                                        catch { }
                                    }
                                    else if (!hasName)
                                    {
                                        // [FIX] Only take DOS name if we don't have ANY name yet.
                                        try { rec.FileName = new string((char*)(fn + 66), 0, nameLen); hasName = true; }
                                        catch { }
                                    }
                                }
                            }
                        }
                    }
                    else if (attrType == 0x80) // $DATA
                    {
                        if (*(attr + 9) == 0) // unnamed
                        {
                            if (*(attr + 8) == 0) // resident
                                rec.FileSize = (long)(*(uint*)(attr + 16));
                            else if (attr + 56 <= pEnd) // non-resident
                                rec.FileSize = *(long*)(attr + 48);
                            hasSize = true;
                        }
                    }
                    else if (attrType > 0x80 && hasName)
                    {
                        // If we are past $DATA, and we have a name, usually we are done.
                        // However, we only stop if we are happy with the name we found.
                        if (hasWin32Name) break; 
                    }

                    attr += attrLen;
                    
                    // [FIX] Don't break on just "hasName". Wait for "hasWin32Name".
                    if (hasWin32Name && (hasSize || isDir)) break;
                }

                if (!isDir && rec.FileSize == 0 && fileNameSize > 0)
                    rec.FileSize = fileNameSize;

                if (rec.FileName != null)
                    _records[recordNumber] = rec;

                recordNumber++;
            }
        }
    }

    private List<MftExtent> ParseMftDataRuns(byte[] rec0, long firstLcn)
    {
        List<MftExtent> extents = new List<MftExtent>();
        if (rec0[0] != 'F' || rec0[1] != 'I' || rec0[2] != 'L' || rec0[3] != 'E') return extents;

        ushort attrOffset = BitConverter.ToUInt16(rec0, 20);
        while (attrOffset < rec0.Length - 8)
        {
            uint attrType = BitConverter.ToUInt32(rec0, attrOffset);
            if (attrType == 0xFFFFFFFF || attrType == 0) break;
            uint attrLength = BitConverter.ToUInt32(rec0, attrOffset + 4);
            if (attrLength == 0 || attrLength > rec0.Length - attrOffset) break;

            if (attrType == 0x80)
            {
                byte nonResident = rec0[attrOffset + 8];
                byte nameLen = rec0[attrOffset + 9];
                if (nameLen == 0 && nonResident == 1)
                {
                    ushort dataRunsOffset = BitConverter.ToUInt16(rec0, attrOffset + 32);
                    int runOffset = attrOffset + dataRunsOffset;
                    long currentLcn = 0;
                    while (runOffset < rec0.Length)
                    {
                        byte header = rec0[runOffset];
                        if (header == 0) break;
                        int lengthSize = header & 0x0F;
                        int offsetSize = (header >> 4) & 0x0F;
                        if (lengthSize == 0 || runOffset + 1 + lengthSize + offsetSize > rec0.Length) break;
                        long clusterCount = 0;
                        for (int i = 0; i < lengthSize; i++)
                            clusterCount |= (long)rec0[runOffset + 1 + i] << (i * 8);
                        long lcnOffset = 0;
                        if (offsetSize > 0)
                        {
                            for (int i = 0; i < offsetSize; i++)
                                lcnOffset |= (long)rec0[runOffset + 1 + lengthSize + i] << (i * 8);
                            if ((rec0[runOffset + 1 + lengthSize + offsetSize - 1] & 0x80) != 0)
                                for (int i = offsetSize; i < 8; i++)
                                    lcnOffset |= (long)0xFF << (i * 8);
                            currentLcn += lcnOffset;
                            extents.Add(new MftExtent { StartLcn = currentLcn, ClusterCount = clusterCount });
                        }
                        runOffset += 1 + lengthSize + offsetSize;
                    }
                    break;
                }
            }
            attrOffset += (ushort)attrLength;
        }
        return extents;
    }

    public string GetFullPath(ulong recordNumber)
    {
        if (_pathCache.ContainsKey(recordNumber)) return _pathCache[recordNumber];
        List<string> parts = new List<string>();
        ulong current = recordNumber;
        int maxDepth = 100;
        while (maxDepth-- > 0)
        {
            FileRecord record;
            if (!_records.TryGetValue(current, out record)) break;
            if (current == 5 || record.ParentRecordNumber == current) { parts.Insert(0, _driveLetter + ":"); break; }
            parts.Insert(0, record.FileName);
            current = record.ParentRecordNumber;
        }
        string path = string.Join(@"\", parts);
        _pathCache[recordNumber] = path;
        return path;
    }

    public void CalculateDirectorySizes() { /* API compat - real work in GetLargestDirectories */ }

    public List<FileItem> GetLargestDirectories(int count)
    {
        const long MAX = 20L * 1024 * 1024 * 1024 * 1024;
        Dictionary<ulong, long> directFileSizes = new Dictionary<ulong, long>();
        foreach (var kvp in _records)
        {
            FileRecord rec = kvp.Value;
            if (!rec.IsDirectory && rec.FileSize > 0 && rec.FileSize < MAX)
            {
                ulong pid = rec.ParentRecordNumber;
                long existing;
                if (directFileSizes.TryGetValue(pid, out existing)) directFileSizes[pid] = existing + rec.FileSize;
                else directFileSizes[pid] = rec.FileSize;
            }
        }

        Dictionary<ulong, List<ulong>> childDirs = new Dictionary<ulong, List<ulong>>();
        foreach (var kvp in _records)
        {
            if (kvp.Value.IsDirectory && kvp.Value.ParentRecordNumber != kvp.Key)
            {
                ulong pid = kvp.Value.ParentRecordNumber;
                List<ulong> children;
                if (!childDirs.TryGetValue(pid, out children)) { children = new List<ulong>(); childDirs[pid] = children; }
                children.Add(kvp.Key);
            }
        }

        Dictionary<ulong, long> cumSizes = new Dictionary<ulong, long>();
        HashSet<ulong> processed = new HashSet<ulong>();
        Queue<ulong> toProcess = new Queue<ulong>();
        Dictionary<ulong, int> pending = new Dictionary<ulong, int>();

        foreach (var kvp in _records)
        {
            if (!kvp.Value.IsDirectory) continue;
            List<ulong> ch;
            int cc = childDirs.TryGetValue(kvp.Key, out ch) ? ch.Count : 0;
            pending[kvp.Key] = cc;
            if (cc == 0) toProcess.Enqueue(kvp.Key);
        }

        while (toProcess.Count > 0)
        {
            ulong dirId = toProcess.Dequeue();
            if (processed.Contains(dirId)) continue;
            processed.Add(dirId);
            long size; directFileSizes.TryGetValue(dirId, out size);
            List<ulong> dc;
            if (childDirs.TryGetValue(dirId, out dc))
                foreach (ulong cid in dc) { long cs; if (cumSizes.TryGetValue(cid, out cs)) size += cs; }
            cumSizes[dirId] = size;
            FileRecord dr;
            if (_records.TryGetValue(dirId, out dr) && dr.ParentRecordNumber != dirId)
            {
                int p; if (pending.TryGetValue(dr.ParentRecordNumber, out p))
                { pending[dr.ParentRecordNumber] = p - 1; if (p - 1 <= 0 && !processed.Contains(dr.ParentRecordNumber)) toProcess.Enqueue(dr.ParentRecordNumber); }
            }
        }

        foreach (var kvp in _records)
        {
            if (!kvp.Value.IsDirectory || processed.Contains(kvp.Key)) continue;
            processed.Add(kvp.Key);
            long size; directFileSizes.TryGetValue(kvp.Key, out size);
            List<ulong> dc;
            if (childDirs.TryGetValue(kvp.Key, out dc))
                foreach (ulong cid in dc) { long cs; if (cumSizes.TryGetValue(cid, out cs)) size += cs; }
            cumSizes[kvp.Key] = size;
        }

        for (int pass = 0; pass < 100; pass++)
        {
            bool changed = false;
            foreach (var kvp in _records)
            {
                if (!kvp.Value.IsDirectory) continue;
                long cur; if (!cumSizes.TryGetValue(kvp.Key, out cur)) continue;
                long ns; directFileSizes.TryGetValue(kvp.Key, out ns);
                List<ulong> dc;
                if (childDirs.TryGetValue(kvp.Key, out dc))
                    foreach (ulong cid in dc) { long cs; if (cumSizes.TryGetValue(cid, out cs)) ns += cs; }
                if (ns != cur) { cumSizes[kvp.Key] = ns; changed = true; }
            }
            if (!changed) break;
        }

        List<KeyValuePair<ulong, long>> sorted = new List<KeyValuePair<ulong, long>>(cumSizes);
        sorted.Sort((a, b) => b.Value.CompareTo(a.Value));
        List<FileItem> results = new List<FileItem>();
        int added = 0;
        foreach (var kvp in sorted)
        {
            if (added >= count) break;
            if (kvp.Value <= 0) continue;
            FileRecord r; if (!_records.TryGetValue(kvp.Key, out r)) continue;
            string path = GetFullPath(kvp.Key);
            if (string.IsNullOrEmpty(path) || !path.Contains(":") || path.Contains("$")) continue;
            results.Add(new FileItem { FullPath = path, Size = kvp.Value, IsDirectory = true });
            added++;
        }
        return results;
    }

    public List<FileItem> GetLargestFiles(int count)
    {
        const long MAX = 20L * 1024 * 1024 * 1024 * 1024;
        List<KeyValuePair<ulong, FileRecord>> files = new List<KeyValuePair<ulong, FileRecord>>();
        foreach (var kvp in _records)
            if (!kvp.Value.IsDirectory && kvp.Value.FileSize > 0 && kvp.Value.FileSize < MAX)
                files.Add(kvp);
        files.Sort((a, b) => b.Value.FileSize.CompareTo(a.Value.FileSize));
        List<FileItem> results = new List<FileItem>();
        int added = 0;
        foreach (var kvp in files)
        {
            if (added >= count) break;
            string path = GetFullPath(kvp.Key);
            if (string.IsNullOrEmpty(path) || !path.Contains(":") || path.Contains("$")) continue;
            results.Add(new FileItem { FullPath = path, Size = kvp.Value.FileSize, IsDirectory = false });
            added++;
        }
        return results;
    }

    public int RecordCount { get { return _records.Count; } }
    public long TotalRecordsScanned { get { return _totalRecordsScanned; } }
}
'@

#endregion

#region Helper Functions

function Format-FileSize {
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
        Compiles MftReader with /optimize+ and /unsafe via CSharpCodeProvider.
        This is CRITICAL â€” Add-Type compiles in Debug mode with zero optimizations.
        CSharpCodeProvider with /optimize+ enables JIT inlining, loop optimizations,
        and combined with /unsafe allows pointer-based parsing with no bounds checks.
    #>
    if (-not ([System.Management.Automation.PSTypeName]'MftReader').Type) {
        $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $params = New-Object System.CodeDom.Compiler.CompilerParameters
        $params.GenerateInMemory = $true
        $params.GenerateExecutable = $false
        $params.CompilerOptions = '/optimize+ /unsafe'
        $params.ReferencedAssemblies.Add('System.dll')
        $params.ReferencedAssemblies.Add('System.Core.dll')
        if ([string]::IsNullOrEmpty($script:CSharpCode)) { throw "CSharpCode is null or empty!" }
        $result = $provider.CompileAssemblyFromSource($params, $script:CSharpCode)
        
        if ($result.Errors.HasErrors) {
            $errorMsg = "C# compilation failed:`n"
            foreach ($err in $result.Errors) {
                $errorMsg += "  Line $($err.Line): $($err.ErrorText)`n"
            }
            throw $errorMsg
        }
    }
}

function Export-DiskSpaceHtml {
    param(
        [Parameter(Mandatory)][array]$Results,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter()][string]$DriveLetter,
        [Parameter()][datetime]$ScanDateStart,
        [Parameter()][datetime]$ScanDateEnd,
        [Parameter()][timespan]$ScanTime
    )

    function Get-NormalizedComputerName {
        param($ComputerName)
        if ($null -eq $ComputerName) { return $env:COMPUTERNAME }
        if ($ComputerName -is [string]) { return $ComputerName }
        if ($ComputerName -is [array]) { return [string]$ComputerName[0] }
        return [string]$ComputerName
    }
    
    $uniqueComputers = @{}
    foreach ($result in $Results) {
        $compName = Get-NormalizedComputerName $result.ComputerName
        if (-not $uniqueComputers.ContainsKey($compName)) {
            $uniqueComputers[$compName] = [System.Collections.Generic.List[object]]::new()
        }
        $uniqueComputers[$compName].Add($result)
    }
    $computerGroups = @($uniqueComputers.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Name = $_.Key; Group = $_.Value } })
    $isMultiComputer = $computerGroups.Count -gt 1
    
    $totalSizeAll = 0
    foreach ($group in $computerGroups) {
        $dirs = $group.Group | Where-Object { $_.Type -eq 'Directory' }
        if ($dirs.Count -gt 0) { $totalSizeAll += ($dirs | Select-Object -First 1).Size }
    }
    $totalSizeAllFormatted = Format-FileSize $totalSizeAll
    $scanTimeFormatted = "{0:mm\:ss\.fff}" -f $ScanTime
    
    function Get-BarColorClass {
        param([double]$Percentage)
        if ($Percentage -ge 90) { return "bar-100" } if ($Percentage -ge 80) { return "bar-90" }
        if ($Percentage -ge 70) { return "bar-80" } if ($Percentage -ge 60) { return "bar-70" }
        if ($Percentage -ge 50) { return "bar-60" } if ($Percentage -ge 40) { return "bar-50" }
        if ($Percentage -ge 30) { return "bar-40" } if ($Percentage -ge 20) { return "bar-30" }
        if ($Percentage -ge 10) { return "bar-20" } return "bar-10"
    }
    
    function Build-TreeRows {
        param([array]$Items, [long]$RootSize, [int]$ComputerIndex)
        $rows = ""
        $sortedItems = $Items | Sort-Object -Property Path
        $allPaths = @{}
        foreach ($item in $sortedItems) { $allPaths[$item.Path] = $item }
        $hasChildren = @{}
        foreach ($item in $sortedItems) {
            if ($item.Path -match '^[A-Za-z]:$') { continue }
            $parentPath = Split-Path -Path $item.Path -Parent
            if ($parentPath -and $parentPath.EndsWith('\')) { $parentPath = $parentPath.TrimEnd('\') }
            if ($parentPath -and $allPaths.ContainsKey($parentPath)) { $hasChildren[$parentPath] = $true }
        }
        foreach ($item in $sortedItems) {
            $path = $item.Path
            $escapedPath = [System.Net.WebUtility]::HtmlEncode($path)
            $pathParts = $path -split '\\'
            $level = $pathParts.Count - 1
            if ($path -match '^[A-Za-z]:$') { $level = 0 }
            $displayName = if ($path -match '^[A-Za-z]:$') { $path } else { Split-Path -Path $path -Leaf }
            $escapedName = [System.Net.WebUtility]::HtmlEncode($displayName)
            $parentPath = if ($level -eq 0) { "" } else { $p = Split-Path -Path $path -Parent; if ($p -and $p.EndsWith('\')) { $p.TrimEnd('\') } else { $p } }
            $escapedParent = [System.Net.WebUtility]::HtmlEncode($parentPath)
            $percentage = if ($RootSize -gt 0) { [math]::Round(($item.Size / $RootSize) * 100, 1) } else { 0 }
            $barClass = Get-BarColorClass $percentage
            $isFile = $item.Type -eq 'File'
            $rowClass = if ($isFile) { "tree-row file" } else { "tree-row" }
            $icon = if ($isFile) { [char]::ConvertFromUtf32(0x1F4C4) } else { [char]::ConvertFromUtf32(0x1F4C1) }
            $iconClass = if ($isFile) { "file-icon" } else { "folder-icon" }
            $indentHtml = ""; for ($i = 0; $i -lt $level; $i++) { $indentHtml += '<div class="indent-guide"></div>' }
            $showToggle = $hasChildren.ContainsKey($path) -and -not $isFile
            $toggleHtml = if ($showToggle) { '<button class="toggle-btn" onclick="toggleFolder(this, event)">&#x25B6;</button>' } else { '<span class="toggle-placeholder"></span>' }
            $hiddenClass = if ($level -gt 0) { " hidden" } else { "" }
            $rows += @"
                    <div class="$rowClass$hiddenClass" data-level="$level" data-path="$escapedPath" data-parent="$escapedParent" data-computer="$ComputerIndex">
                        <div class="tree-name"><div class="tree-indent">$indentHtml $toggleHtml</div><span class="item-icon $iconClass">$icon</span><span class="item-label" title="$escapedPath">$escapedName</span></div>
                        <span class="tree-percent">$percentage%</span><span class="tree-size">$($item.SizeFormatted)</span>
                        <div class="tree-bar"><div class="tree-bar-fill $barClass" style="width: $percentage%"></div></div>
                    </div>
"@
        }
        return $rows
    }
    
    $computerSections = ""
    $computerIndex = 0
    $headerColors = @("", "server2", "server3", "server4", "server5")
    foreach ($group in $computerGroups) {
        $computerName = $group.Name; $computerItems = $group.Group
        $dirs = $computerItems | Where-Object { $_.Type -eq 'Directory' }
        $files = $computerItems | Where-Object { $_.Type -eq 'File' }
        $rootSize = if ($dirs.Count -gt 0) { ($dirs | Select-Object -First 1).Size } else { 0 }
        $rootSizeFormatted = Format-FileSize $rootSize
        $compScanTime = if ($computerItems.Count -gt 0) { $computerItems[0].ScanTime } else { [timespan]::Zero }
        $compScanTimeFormatted = "{0:mm\:ss\.fff}" -f $compScanTime
        $compScanEnd = if ($computerItems.Count -gt 0 -and $computerItems[0].ScanDateEnd) { $computerItems[0].ScanDateEnd.ToString('HH:mm:ss') } else { "N/A" }
        $headerColorClass = $headerColors[$computerIndex % $headerColors.Count]
        $allItems = @(); $allItems += $dirs; $allItems += $files
        $treeRows = Build-TreeRows -Items $allItems -RootSize $rootSize -ComputerIndex $computerIndex
        $computerSections += @"
        <div class="computer-section">
            <div class="computer-header $headerColorClass" onclick="toggleComputer(this)">
                <div class="computer-info"><button class="computer-toggle expanded">&#x25B6;</button><span class="computer-icon">&#x1F5A5;</span><span class="computer-name">$computerName</span><span class="computer-drive">${DriveLetter}:\</span><span class="status-badge status-online">&#x2713; Scanned</span></div>
                <div class="computer-stats"><div class="computer-stat"><span class="computer-stat-label">Total Size</span><span class="computer-stat-value size">$rootSizeFormatted</span></div><div class="computer-stat"><span class="computer-stat-label">Scan Time</span><span class="computer-stat-value time">$compScanTimeFormatted</span></div><div class="computer-stat"><span class="computer-stat-label">Completed</span><span class="computer-stat-value">$compScanEnd</span></div></div>
            </div>
            <div class="tree-container"><div class="tree-header"><span>Name</span><span>Percent</span><span>Size</span><span>Size Graph</span></div><div class="tree-body">
$treeRows
            </div></div>
        </div>
"@
        $computerIndex++
    }
    
    $mainHeaderTitle = if ($isMultiComputer) { "Multi-Computer Disk Analysis" } else { "Disk Space Analysis" }
    $mainHeaderSubtitle = if ($isMultiComputer) { "Drive ${DriveLetter}:\ across $($computerGroups.Count) servers" } else { "Drive ${DriveLetter}:\ on $($computerGroups[0].Name)" }
    $mainStatsHtml = if ($isMultiComputer) { @"
            <div class="main-stats"><div class="main-stat"><div class="main-stat-value">$($computerGroups.Count)</div><div class="main-stat-label">Computers</div></div><div class="main-stat"><div class="main-stat-value">$totalSizeAllFormatted</div><div class="main-stat-label">Total Analyzed</div></div><div class="main-stat"><div class="main-stat-value">$scanTimeFormatted</div><div class="main-stat-label">Total Duration</div></div></div>
"@ } else { @"
            <div class="main-stats"><div class="main-stat"><div class="main-stat-value">$totalSizeAllFormatted</div><div class="main-stat-label">Total Size</div></div><div class="main-stat"><div class="main-stat-value">$($ScanDateStart.ToString('HH:mm:ss'))</div><div class="main-stat-label">Started</div></div><div class="main-stat"><div class="main-stat-value">$($ScanDateEnd.ToString('HH:mm:ss'))</div><div class="main-stat-label">Completed</div></div><div class="main-stat"><div class="main-stat-value">$scanTimeFormatted</div><div class="main-stat-label">Duration</div></div></div>
"@ }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$mainHeaderTitle - ${DriveLetter}:\</title>
    <style>
        :root { --bg-primary: #1e1e2e; --bg-secondary: #282839; --bg-hover: #313244; --bg-selected: #3d3d54; --text-primary: #cdd6f4; --text-secondary: #a6adc8; --text-muted: #6c7086; --border-color: #45475a; --accent-blue: #89b4fa; --accent-green: #a6e3a1; --accent-yellow: #f9e2af; --accent-peach: #fab387; --accent-red: #f38ba8; --accent-mauve: #cba6f7; --accent-teal: #94e2d5; --folder-yellow: #f9e2af; --file-blue: #89b4fa; --bar-bg: #45475a; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', -apple-system, sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; line-height: 1.4; font-size: 14px; }
        .container { max-width: 1600px; margin: 0 auto; padding: 1rem; }
        .main-header { background: linear-gradient(135deg, #313244 0%, #282839 100%); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; }
        .main-header-title { display: flex; align-items: center; gap: 0.75rem; }
        .main-header-title .icon { font-size: 1.75rem; } .main-header-title h1 { font-size: 1.35rem; font-weight: 600; } .main-header-title .subtitle { font-size: 0.85rem; color: var(--text-muted); }
        .main-stats { display: flex; gap: 2rem; flex-wrap: wrap; } .main-stat { text-align: center; } .main-stat-value { font-family: monospace; font-size: 1.5rem; font-weight: 600; color: var(--accent-blue); } .main-stat-label { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; }
        .computer-section { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
        .computer-header { display: flex; align-items: center; justify-content: space-between; padding: 1rem 1.25rem; background: linear-gradient(90deg, rgba(137,180,250,0.1) 0%, transparent 100%); border-bottom: 1px solid var(--border-color); cursor: pointer; }
        .computer-header:hover { background: linear-gradient(90deg, rgba(137,180,250,0.15) 0%, rgba(137,180,250,0.05) 100%); }
        .computer-header.server2 { background: linear-gradient(90deg, rgba(166,227,161,0.1) 0%, transparent 100%); }
        .computer-header.server3 { background: linear-gradient(90deg, rgba(249,226,175,0.1) 0%, transparent 100%); }
        .computer-info { display: flex; align-items: center; gap: 1rem; }
        .computer-toggle { width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; background: none; border: none; color: var(--text-muted); cursor: pointer; border-radius: 4px; font-size: 0.8rem; } .computer-toggle.expanded { transform: rotate(90deg); }
        .computer-icon { font-size: 1.5rem; } .computer-name { font-weight: 600; font-size: 1.1rem; }
        .computer-drive { font-family: monospace; font-size: 0.9rem; color: var(--accent-blue); background: rgba(137,180,250,0.15); padding: 0.25rem 0.5rem; border-radius: 4px; }
        .computer-stats { display: flex; gap: 1.5rem; } .computer-stat { display: flex; flex-direction: column; align-items: flex-end; gap: 0.125rem; }
        .computer-stat-label { font-size: 0.65rem; color: var(--text-muted); text-transform: uppercase; } .computer-stat-value { font-family: monospace; font-size: 0.9rem; font-weight: 500; } .computer-stat-value.size { color: var(--accent-blue); font-size: 1rem; } .computer-stat-value.time { color: var(--accent-green); }
        .tree-container { overflow: hidden; } .tree-container.collapsed { display: none; }
        .tree-header { display: grid; grid-template-columns: 1fr 100px 140px 200px; gap: 1rem; padding: 0.6rem 1rem; background: var(--bg-primary); border-bottom: 1px solid var(--border-color); font-size: 0.7rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; }
        .tree-header span:nth-child(2), .tree-header span:nth-child(3) { text-align: right; }
        .tree-body { max-height: 500px; overflow-y: auto; }
        .tree-row { display: grid; grid-template-columns: 1fr 100px 140px 200px; gap: 1rem; padding: 0.45rem 1rem; border-bottom: 1px solid var(--border-color); cursor: pointer; align-items: center; }
        .tree-row:hover { background: var(--bg-hover); } .tree-row.selected { background: var(--bg-selected); } .tree-row.hidden { display: none; }
        .tree-row.file { background: rgba(0,0,0,0.1); } .tree-row.file:hover { background: var(--bg-hover); }
        .tree-name { display: flex; align-items: center; gap: 0.5rem; min-width: 0; }
        .tree-indent { display: flex; align-items: center; flex-shrink: 0; }
        .indent-guide { width: 20px; height: 100%; position: relative; flex-shrink: 0; } .indent-guide::before { content: ''; position: absolute; left: 9px; top: 0; bottom: 0; width: 1px; background: var(--border-color); }
        .toggle-btn { width: 18px; height: 18px; display: flex; align-items: center; justify-content: center; background: none; border: none; color: var(--text-muted); cursor: pointer; border-radius: 4px; flex-shrink: 0; font-size: 0.65rem; }
        .toggle-btn.expanded { transform: rotate(90deg); } .toggle-placeholder { width: 18px; flex-shrink: 0; }
        .item-icon { font-size: 0.95rem; flex-shrink: 0; } .folder-icon { color: var(--folder-yellow); } .file-icon { color: var(--file-blue); }
        .item-label { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 0.9rem; } .tree-row.file .item-label { color: var(--text-secondary); }
        .tree-percent { font-family: monospace; font-size: 0.8rem; text-align: right; color: var(--text-secondary); }
        .tree-size { font-family: monospace; font-size: 0.8rem; text-align: right; font-weight: 500; }
        .tree-bar { height: 16px; background: var(--bar-bg); border-radius: 3px; overflow: hidden; } .tree-bar-fill { height: 100%; border-radius: 3px; }
        .tree-row.file .tree-bar-fill { background: linear-gradient(90deg, var(--accent-mauve), var(--accent-blue)); opacity: 0.7; }
        .bar-100 { background: linear-gradient(90deg, #89b4fa, #b4befe); } .bar-90 { background: linear-gradient(90deg, #94e2d5, #89dceb); } .bar-80 { background: linear-gradient(90deg, #a6e3a1, #94e2d5); } .bar-70 { background: linear-gradient(90deg, #f9e2af, #a6e3a1); } .bar-60 { background: linear-gradient(90deg, #fab387, #f9e2af); } .bar-50 { background: linear-gradient(90deg, #eba0ac, #fab387); } .bar-40 { background: linear-gradient(90deg, #f38ba8, #eba0ac); } .bar-30 { background: linear-gradient(90deg, #cba6f7, #f38ba8); } .bar-20 { background: linear-gradient(90deg, #b4befe, #cba6f7); } .bar-10 { background: linear-gradient(90deg, #89b4fa, #b4befe); }
        .status-badge { font-size: 0.65rem; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 500; text-transform: uppercase; } .status-online { background: rgba(166,227,161,0.2); color: var(--accent-green); }
        .footer { text-align: center; padding: 1rem; color: var(--text-muted); font-size: 0.8rem; }
        .tree-body::-webkit-scrollbar { width: 8px; } .tree-body::-webkit-scrollbar-track { background: var(--bg-primary); } .tree-body::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 4px; }
        @media (max-width: 1000px) { .tree-header, .tree-row { grid-template-columns: 1fr 80px 100px; } .tree-header span:nth-child(4), .tree-row .tree-bar { display: none; } .computer-stats { display: none; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="main-header"><div class="main-header-title"><span class="icon">&#x1F5A5;</span><div><h1>$mainHeaderTitle</h1><div class="subtitle">$mainHeaderSubtitle</div></div></div>
$mainStatsHtml
        </div>
$computerSections
        <div class="footer">Generated by <strong>DiskSpaceAnalyzer</strong> &bull; $($ScanDateEnd.ToString('yyyy-MM-dd HH:mm:ss'))</div>
    </div>
    <script>
        function toggleComputer(header) { header.querySelector('.computer-toggle').classList.toggle('expanded'); header.nextElementSibling.classList.toggle('collapsed'); }
        function toggleFolder(btn, event) {
            event.stopPropagation(); const row = btn.closest('.tree-row'); const path = row.dataset.path; const computer = row.dataset.computer; const isExpanded = btn.classList.contains('expanded'); btn.classList.toggle('expanded');
            row.closest('.tree-body').querySelectorAll('.tree-row').forEach(r => { const parent = r.dataset.parent; if (parent && parent.startsWith(path) && r !== row && r.dataset.computer === computer) { if (isExpanded) { r.classList.add('hidden'); const cb = r.querySelector('.toggle-btn'); if (cb) cb.classList.remove('expanded'); } else { if (r.dataset.parent === path) r.classList.remove('hidden'); } } });
        }
        document.querySelectorAll('.tree-row').forEach(row => { row.addEventListener('click', e => { if (e.target.closest('.toggle-btn')) return; document.querySelectorAll('.tree-row').forEach(r => r.classList.remove('selected')); row.classList.add('selected'); }); });
    </script>
</body></html>
"@
    $html | Out-File -FilePath $OutputPath -Encoding utf8 -Force
    Write-Verbose "HTML report exported to: $OutputPath"
}

#endregion

#region Main Function

function Get-DiskSpaceUsage {
    <#
    .SYNOPSIS
        Fast disk space analyzer using MFT (Master File Table) reading.
    .PARAMETER DriveLetter
        The drive letter to scan (e.g., "C"). Default is "C".
    .PARAMETER TopCount
        Number of top results to return (default: 30, max: 10000).
    .PARAMETER IncludeFiles
        Also include largest individual files in the output.
    .PARAMETER ComputerName
        One or more computer names to analyze remotely.
    .PARAMETER Credential
        Credentials for remote connections.
    .PARAMETER ExportHtml
        Export results to HTML report at specified path.
    .NOTES
        Requires Administrator privileges. Only works with NTFS drives.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][ValidatePattern('^[A-Za-z]$')][string]$DriveLetter = 'C',
        [Parameter()][ValidateRange(1, 10000)][int]$TopCount = 30,
        [Parameter()][switch]$IncludeFiles,
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CN', 'Server', 'PSComputerName')][string[]]$ComputerName,
        [Parameter()][System.Management.Automation.PSCredential][System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,
        [Parameter()][string]$ExportHtml
    )

    begin {
        $analysisScriptBlock = {
            param([string]$DriveLetter, [int]$TopCount, [bool]$IncludeFiles, [string]$CSharpCode)
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) { throw "Administrator privileges required." }
            if (-not ([System.Management.Automation.PSTypeName]'MftReader').Type) {
                $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
                $params = New-Object System.CodeDom.Compiler.CompilerParameters
                $params.GenerateInMemory = $true; $params.GenerateExecutable = $false
                $params.CompilerOptions = '/optimize+ /unsafe'
                $params.ReferencedAssemblies.Add('System.dll'); $params.ReferencedAssemblies.Add('System.Core.dll')
                $result = $provider.CompileAssemblyFromSource($params, $CSharpCode)
                if ($result.Errors.HasErrors) { $msg = ""; foreach ($e in $result.Errors) { $msg += "Line $($e.Line): $($e.ErrorText)`n" }; throw $msg }
            }
            $scanDateStart = Get-Date
            $reader = New-Object MftReader($DriveLetter); $reader.ReadMft($null); $reader.CalculateDirectorySizes()
            $scanDateEnd = Get-Date; $scanTime = $scanDateEnd - $scanDateStart
            $results = @(); $cn = $env:COMPUTERNAME
            $dirs = $reader.GetLargestDirectories($TopCount); $rank = 1
            foreach ($dir in $dirs) {
                $results += [PSCustomObject]@{ ComputerName=$cn; Rank=$rank; Path=$dir.FullPath; Size=$dir.Size
                    SizeFormatted = if ($dir.Size -ge 1TB) { "{0:F2} TB" -f ($dir.Size/1TB) } elseif ($dir.Size -ge 1GB) { "{0:F2} GB" -f ($dir.Size/1GB) } elseif ($dir.Size -ge 1MB) { "{0:F2} MB" -f ($dir.Size/1MB) } elseif ($dir.Size -ge 1KB) { "{0:F2} KB" -f ($dir.Size/1KB) } else { "$($dir.Size) B" }
                    SizeKB=[math]::Round($dir.Size/1KB,2); SizeMB=[math]::Round($dir.Size/1MB,2); SizeGB=[math]::Round($dir.Size/1GB,2)
                    Type='Directory'; ScanDateStart=$scanDateStart; ScanDateEnd=$scanDateEnd; ScanTime=$scanTime }
                $rank++
            }
            if ($IncludeFiles) {
                $files = $reader.GetLargestFiles($TopCount); $rank = 1
                foreach ($file in $files) {
                    $results += [PSCustomObject]@{ ComputerName=$cn; Rank=$rank; Path=$file.FullPath; Size=$file.Size
                        SizeFormatted = if ($file.Size -ge 1TB) { "{0:F2} TB" -f ($file.Size/1TB) } elseif ($file.Size -ge 1GB) { "{0:F2} GB" -f ($file.Size/1GB) } elseif ($file.Size -ge 1MB) { "{0:F2} MB" -f ($file.Size/1MB) } elseif ($file.Size -ge 1KB) { "{0:F2} KB" -f ($file.Size/1KB) } else { "$($file.Size) B" }
                        SizeKB=[math]::Round($file.Size/1KB,2); SizeMB=[math]::Round($file.Size/1MB,2); SizeGB=[math]::Round($file.Size/1GB,2)
                        Type='File'; ScanDateStart=$scanDateStart; ScanDateEnd=$scanDateEnd; ScanTime=$scanTime }
                    $rank++
                }
            }
            return $results
        }
        $allComputers = [System.Collections.Generic.List[string]]::new()
        $allResults = [System.Collections.Generic.List[object]]::new()
        $scanStartTime = $null; $scanEndTime = $null
    }

    process {
        if ($ComputerName) { foreach ($computer in $ComputerName) { $allComputers.Add($computer) } }
    }

    end {
        if ($allComputers.Count -eq 0) {
            Write-Verbose "Analyzing local computer drive $($DriveLetter):\"
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) { throw "Administrator privileges required." }
            try {
                Initialize-MftReaderType
                $reader = New-Object MftReader($DriveLetter)
                $scanDateStart = Get-Date
                Write-Verbose "Reading MFT from drive $($DriveLetter):\..."
                $reader.ReadMft($null)
                Write-Verbose "MFT read complete: $($reader.RecordCount.ToString('N0')) valid records out of $($reader.TotalRecordsScanned.ToString('N0')) total slots"
                Write-Verbose "Timing: I/O=$($reader.IoTimeMs)ms  Parse=$($reader.ParseTimeMs)ms  Total=$($reader.TotalTimeMs)ms"
                Write-Verbose "Calculating directory sizes..."
                $reader.CalculateDirectorySizes()
                $scanDateEnd = Get-Date; $scanTime = $scanDateEnd - $scanDateStart
                $computerName = $env:COMPUTERNAME
                $dirs = $reader.GetLargestDirectories($TopCount); $rank = 1
                foreach ($dir in $dirs) {
                    $result = [PSCustomObject]@{ ComputerName=$computerName; Rank=$rank; Path=$dir.FullPath; Size=$dir.Size; SizeFormatted=Format-FileSize $dir.Size
                        SizeKB=[math]::Round($dir.Size/1KB,2); SizeMB=[math]::Round($dir.Size/1MB,2); SizeGB=[math]::Round($dir.Size/1GB,2)
                        Type='Directory'; ScanDateStart=$scanDateStart; ScanDateEnd=$scanDateEnd; ScanTime=$scanTime }
                    $allResults.Add($result); $result; $rank++
                }
                if ($IncludeFiles) {
                    $files = $reader.GetLargestFiles($TopCount); $rank = 1
                    foreach ($file in $files) {
                        $result = [PSCustomObject]@{ ComputerName=$computerName; Rank=$rank; Path=$file.FullPath; Size=$file.Size; SizeFormatted=Format-FileSize $file.Size
                            SizeKB=[math]::Round($file.Size/1KB,2); SizeMB=[math]::Round($file.Size/1MB,2); SizeGB=[math]::Round($file.Size/1GB,2)
                            Type='File'; ScanDateStart=$scanDateStart; ScanDateEnd=$scanDateEnd; ScanTime=$scanTime }
                        $allResults.Add($result); $result; $rank++
                    }
                }
                $scanStartTime = $scanDateStart; $scanEndTime = $scanDateEnd
            } catch { Write-Error "Error analyzing local computer: $_" }
        }
        else {
            # 1. Prepare parameters for the bulk execution
$invokeParams = @{
    ComputerName = $allComputers
    ScriptBlock  = $analysisScriptBlock
    ArgumentList = @($DriveLetter, $TopCount, $IncludeFiles.IsPresent, $script:CSharpCode)
    ErrorAction  = 'Continue'  # Important: Ensures one offline PC doesn't stop the whole batch
}

# Add credential only if present
if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) { 
    $invokeParams['Credential'] = $Credential 
}

Write-Verbose "Analyzing Drive $($DriveLetter): on $($allComputers.Count) computers in parallel..."

try {
    # 2. Run against ALL computers at once
    # Use -ErrorVariable to catch failures without stopping the script
    $results = Invoke-Command @invokeParams -ErrorVariable connErrors

    # 3. Process the combined results
    foreach ($result in $results) {
        $out = [PSCustomObject]@{
            # PSComputerName is automatically added by Invoke-Command
            ComputerName  = $result.PSComputerName 
            Rank          = $result.Rank
            Path          = $result.Path
            Size          = $result.Size
            SizeFormatted = $result.SizeFormatted
            SizeKB        = $result.SizeKB
            SizeMB        = $result.SizeMB
            SizeGB        = $result.SizeGB
            Type          = $result.Type
            ScanDateStart = $result.ScanDateStart
            ScanDateEnd   = $result.ScanDateEnd
            ScanTime      = $result.ScanTime
        }

        $allResults.Add($out); $out

        # Update global start/end times based on the results coming back
        if ($null -eq $scanStartTime -or $result.ScanDateStart -lt $scanStartTime) { $scanStartTime = $result.ScanDateStart }
        if ($null -eq $scanEndTime -or $result.ScanDateEnd -gt $scanEndTime) { $scanEndTime = $result.ScanDateEnd }
    }

    # Optional: Log computers that failed to connect
    if ($connErrors) {
        foreach ($err in $connErrors) {
            Write-Error "Connection failed for $($err.TargetObject): $($err.Exception.Message)"
        }
    }

} catch {
    Write-Error "Fatal error during bulk Invoke-Command: $_"
}
        }
        if ($ExportHtml -and $allResults.Count -gt 0) {
            $totalScanTime = if ($scanStartTime -and $scanEndTime) { $scanEndTime - $scanStartTime } else { [timespan]::Zero }
            Export-DiskSpaceHtml -Results $allResults -OutputPath $ExportHtml -DriveLetter $DriveLetter -ScanDateStart $scanStartTime -ScanDateEnd $scanEndTime -ScanTime $totalScanTime
            Write-Host "HTML report exported to: $ExportHtml" -ForegroundColor Green
        }
    }
}

#endregion

Export-ModuleMember -Function Get-DiskSpaceUsage
