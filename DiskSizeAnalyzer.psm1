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

    // Structure to hold MFT extent information (for fragmented MFT)
    private struct MftExtent
    {
        public long StartLcn;      // Logical cluster number where this extent starts
        public long ClusterCount;  // Number of clusters in this extent
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

            int recordSize = (int)volumeData.BytesPerFileRecordSegment;
            int clusterSize = (int)volumeData.BytesPerCluster;
            long mftSize = volumeData.MftValidDataLength;
            long totalRecords = mftSize / recordSize;
            long mftStartByte = volumeData.MftStartLcn * clusterSize;

            // Step 1: Read MFT record 0 to get the MFT's own data runs (extent list)
            byte[] mftRecord0 = new byte[recordSize];
            long newPointer;
            
            if (!SetFilePointerEx(volumeHandle, mftStartByte, out newPointer, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to seek to MFT start");

            uint bytesRead;
            if (!ReadFile(volumeHandle, mftRecord0, (uint)recordSize, out bytesRead, IntPtr.Zero) || bytesRead < recordSize)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to read MFT record 0");

            // Step 2: Parse data runs from MFT record 0's $DATA attribute
            List<MftExtent> mftExtents = ParseMftDataRuns(mftRecord0, volumeData.MftStartLcn);
            
            if (mftExtents.Count == 0)
            {
                // Fallback: assume contiguous MFT (old behavior)
                mftExtents.Add(new MftExtent 
                { 
                    StartLcn = volumeData.MftStartLcn, 
                    ClusterCount = (mftSize + clusterSize - 1) / clusterSize 
                });
            }

            // Step 3: Read MFT records from all extents
            byte[] recordBuffer = new byte[recordSize];
            ulong recordNumber = 0;
            int lastProgress = -1;
            int recordsPerCluster = clusterSize / recordSize;

            foreach (MftExtent extent in mftExtents)
            {
                long extentStartByte = extent.StartLcn * clusterSize;
                long extentRecordCount = extent.ClusterCount * recordsPerCluster;

                for (long i = 0; i < extentRecordCount && recordNumber < (ulong)totalRecords; i++)
                {
                    long currentOffset = extentStartByte + (i * recordSize);

                    if (!SetFilePointerEx(volumeHandle, currentOffset, out newPointer, 0))
                    {
                        recordNumber++;
                        continue;
                    }

                    if (!ReadFile(volumeHandle, recordBuffer, (uint)recordSize, out bytesRead, IntPtr.Zero) || bytesRead < recordSize)
                    {
                        recordNumber++;
                        continue;
                    }

                    FileRecord record = ParseMftRecord(recordBuffer, recordNumber);
                    if (record != null && record.IsValid && !record.IsDeleted)
                    {
                        _records[recordNumber] = record;
                    }

                    recordNumber++;

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
    }

    // Parse the data runs from MFT record 0's $DATA attribute to find all MFT extents
    private List<MftExtent> ParseMftDataRuns(byte[] mftRecord0, long firstLcn)
    {
        List<MftExtent> extents = new List<MftExtent>();

        // Check FILE signature
        if (mftRecord0[0] != 'F' || mftRecord0[1] != 'I' || mftRecord0[2] != 'L' || mftRecord0[3] != 'E')
            return extents;

        // Get first attribute offset
        ushort attrOffset = BitConverter.ToUInt16(mftRecord0, 20);

        // Find the $DATA attribute (type 0x80)
        while (attrOffset < mftRecord0.Length - 8)
        {
            uint attrType = BitConverter.ToUInt32(mftRecord0, attrOffset);

            if (attrType == 0xFFFFFFFF || attrType == 0)
                break;

            uint attrLength = BitConverter.ToUInt32(mftRecord0, attrOffset + 4);
            if (attrLength == 0 || attrLength > mftRecord0.Length - attrOffset)
                break;

            // $DATA attribute (0x80)
            if (attrType == 0x80)
            {
                byte nonResident = mftRecord0[attrOffset + 8];
                byte nameLen = mftRecord0[attrOffset + 9];

                // We want the unnamed $DATA attribute and it must be non-resident
                if (nameLen == 0 && nonResident == 1)
                {
                    // Data runs offset is at attrOffset + 32 (for non-resident attributes)
                    ushort dataRunsOffset = BitConverter.ToUInt16(mftRecord0, attrOffset + 32);
                    int runOffset = attrOffset + dataRunsOffset;

                    // Parse the data runs
                    long currentLcn = 0;

                    while (runOffset < mftRecord0.Length)
                    {
                        byte header = mftRecord0[runOffset];
                        if (header == 0)
                            break; // End of data runs

                        int lengthSize = header & 0x0F;        // Low nibble: length field size
                        int offsetSize = (header >> 4) & 0x0F; // High nibble: offset field size

                        if (lengthSize == 0 || runOffset + 1 + lengthSize + offsetSize > mftRecord0.Length)
                            break;

                        // Read cluster count (length)
                        long clusterCount = 0;
                        for (int i = 0; i < lengthSize; i++)
                        {
                            clusterCount |= (long)mftRecord0[runOffset + 1 + i] << (i * 8);
                        }

                        // Read LCN offset (signed, relative to previous LCN)
                        long lcnOffset = 0;
                        if (offsetSize > 0)
                        {
                            for (int i = 0; i < offsetSize; i++)
                            {
                                lcnOffset |= (long)mftRecord0[runOffset + 1 + lengthSize + i] << (i * 8);
                            }

                            // Sign extend if negative
                            if ((mftRecord0[runOffset + 1 + lengthSize + offsetSize - 1] & 0x80) != 0)
                            {
                                for (int i = offsetSize; i < 8; i++)
                                {
                                    lcnOffset |= (long)0xFF << (i * 8);
                                }
                            }

                            currentLcn += lcnOffset;

                            extents.Add(new MftExtent
                            {
                                StartLcn = currentLcn,
                                ClusterCount = clusterCount
                            });
                        }
                        // If offsetSize is 0, it's a sparse run (no physical clusters) - skip it

                        runOffset += 1 + lengthSize + offsetSize;
                    }

                    break; // Found and processed $DATA, exit attribute loop
                }
            }

            attrOffset += (ushort)attrLength;
        }

        return extents;
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

        // Track file size from $FILE_NAME as fallback (for files with $DATA in extension records)
        long fileNameSize = 0;

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
                        
                        // Keep track of largest file size from $FILE_NAME attributes
                        // (file may have multiple $FILE_NAME attrs for different namespaces)
                        if (fnFileSize > fileNameSize)
                            fileNameSize = fnFileSize;

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
                        // Need at least 56 bytes from attrOffset to read the 8-byte size at offset 48
                        if (attrOffset + 56 <= buffer.Length)
                        {
                            record.FileSize = BitConverter.ToInt64(buffer, attrOffset + 48);
                        }
                    }
                }
            }

            attrOffset += (ushort)attrLength;
        }

        // CRITICAL FIX: Use $FILE_NAME size as fallback when:
        // 1. No $DATA attribute found (it's in an extension record via $ATTRIBUTE_LIST)
        // 2. $DATA was found but size is 0 (parsing issue)
        // The $FILE_NAME size may be slightly stale but is accurate enough for disk analysis
        if (!record.IsDirectory && record.FileSize == 0 && fileNameSize > 0)
        {
            record.FileSize = fileNameSize;
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
        
        // FALLBACK PASS: Process any directories that got stuck due to orphaned children
        // This handles cases where parent references don't match the actual tree structure
        bool madeProgress = true;
        while (madeProgress)
        {
            madeProgress = false;
            foreach (var kvp in _records)
            {
                if (!kvp.Value.IsDirectory) continue;
                ulong dirId = kvp.Key;
                if (processed.Contains(dirId)) continue;
                
                // Process this stuck directory
                processed.Add(dirId);
                madeProgress = true;
                
                long size = directFileSizes.ContainsKey(dirId) ? directFileSizes[dirId] : 0;
                
                // Add sizes of any child directories that ARE processed
                if (childDirs.ContainsKey(dirId))
                {
                    foreach (ulong childId in childDirs[dirId])
                    {
                        if (cumulativeSizes.ContainsKey(childId))
                            size += cumulativeSizes[childId];
                    }
                }
                
                cumulativeSizes[dirId] = size;
            }
        }
        
        // FINAL ROLLUP: Propagate child sizes up to parents that were processed before their children
        // Multiple passes to handle deep nesting
        for (int pass = 0; pass < 100; pass++)
        {
            bool changed = false;
            foreach (var kvp in _records)
            {
                if (!kvp.Value.IsDirectory) continue;
                ulong dirId = kvp.Key;
                if (!cumulativeSizes.ContainsKey(dirId)) continue;
                
                long newSize = directFileSizes.ContainsKey(dirId) ? directFileSizes[dirId] : 0;
                
                if (childDirs.ContainsKey(dirId))
                {
                    foreach (ulong childId in childDirs[dirId])
                    {
                        if (cumulativeSizes.ContainsKey(childId))
                            newSize += cumulativeSizes[childId];
                    }
                }
                
                if (newSize != cumulativeSizes[dirId])
                {
                    cumulativeSizes[dirId] = newSize;
                    changed = true;
                }
            }
            if (!changed) break;
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

function Export-DiskSpaceHtml {
    <#
    .SYNOPSIS
        Exports disk space usage results to a beautiful HTML report with tree view.
    #>
    param(
        [Parameter(Mandatory)]
        [array]$Results,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter()]
        [string]$DriveLetter,
        
        [Parameter()]
        [datetime]$ScanDateStart,
        
        [Parameter()]
        [datetime]$ScanDateEnd,
        
        [Parameter()]
        [timespan]$ScanTime
    )

    # Helper function to normalize computer name (handles arrays)
    function Get-NormalizedComputerName {
        param($ComputerName)
        if ($null -eq $ComputerName) { return $env:COMPUTERNAME }
        if ($ComputerName -is [string]) { return $ComputerName }
        if ($ComputerName -is [array]) { return [string]$ComputerName[0] }
        return [string]$ComputerName
    }
    
    # Get unique computer names first
    $uniqueComputers = @{}
    foreach ($result in $Results) {
        $compName = Get-NormalizedComputerName $result.ComputerName
        if (-not $uniqueComputers.ContainsKey($compName)) {
            $uniqueComputers[$compName] = [System.Collections.Generic.List[object]]::new()
        }
        $uniqueComputers[$compName].Add($result)
    }
    
    # Convert to group-like objects
    $computerGroups = @($uniqueComputers.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Key
            Group = $_.Value
        }
    })
    $isMultiComputer = $computerGroups.Count -gt 1
    
    # Calculate totals across all computers
    $totalSizeAll = 0
    foreach ($group in $computerGroups) {
        $dirs = $group.Group | Where-Object { $_.Type -eq 'Directory' }
        if ($dirs.Count -gt 0) {
            $rootSize = ($dirs | Select-Object -First 1).Size
            $totalSizeAll += $rootSize
        }
    }
    $totalSizeAllFormatted = Format-FileSize $totalSizeAll
    $scanTimeFormatted = "{0:mm\:ss\.fff}" -f $ScanTime
    
    # Helper function to get bar color class based on percentage
    function Get-BarColorClass {
        param([double]$Percentage)
        if ($Percentage -ge 90) { return "bar-100" }
        if ($Percentage -ge 80) { return "bar-90" }
        if ($Percentage -ge 70) { return "bar-80" }
        if ($Percentage -ge 60) { return "bar-70" }
        if ($Percentage -ge 50) { return "bar-60" }
        if ($Percentage -ge 40) { return "bar-50" }
        if ($Percentage -ge 30) { return "bar-40" }
        if ($Percentage -ge 20) { return "bar-30" }
        if ($Percentage -ge 10) { return "bar-20" }
        return "bar-10"
    }
    
    # Helper function to build tree structure from flat results
    function Build-TreeRows {
        param(
            [array]$Items,
            [long]$RootSize,
            [int]$ComputerIndex
        )
        
        $rows = ""
        
        # Sort items by path to ensure proper hierarchy
        $sortedItems = $Items | Sort-Object -Property Path
        
        # Build a lookup of all paths for parent detection
        $allPaths = @{}
        foreach ($item in $sortedItems) {
            $allPaths[$item.Path] = $item
        }
        
        # Track which paths have children (for toggle button)
        $hasChildren = @{}
        foreach ($item in $sortedItems) {
            # Skip root drive paths for parent detection
            if ($item.Path -match '^[A-Za-z]:$') { continue }
            $parentPath = Split-Path -Path $item.Path -Parent
            # Normalize parent path - remove trailing backslash
            if ($parentPath -and $parentPath.EndsWith('\')) {
                $parentPath = $parentPath.TrimEnd('\')
            }
            if ($parentPath -and $allPaths.ContainsKey($parentPath)) {
                $hasChildren[$parentPath] = $true
            }
        }
        
        foreach ($item in $sortedItems) {
            $path = $item.Path
            $escapedPath = [System.Net.WebUtility]::HtmlEncode($path)
            
            # Calculate depth (level) based on path separators
            $pathParts = $path -split '\\'
            $level = $pathParts.Count - 1
            if ($path -match '^[A-Za-z]:$') { $level = 0 }
            
            # Get display name (last part of path)
            $displayName = if ($path -match '^[A-Za-z]:$') { $path } else { Split-Path -Path $path -Leaf }
            $escapedName = [System.Net.WebUtility]::HtmlEncode($displayName)
            
            # Get parent path - normalize by removing trailing backslash
            $parentPath = if ($level -eq 0) { "" } else { 
                $p = Split-Path -Path $path -Parent
                if ($p -and $p.EndsWith('\')) { $p.TrimEnd('\') } else { $p }
            }
            $escapedParent = [System.Net.WebUtility]::HtmlEncode($parentPath)
            
            # Calculate percentage
            $percentage = if ($RootSize -gt 0) { [math]::Round(($item.Size / $RootSize) * 100, 1) } else { 0 }
            $barClass = Get-BarColorClass $percentage
            
            # Determine if this is a file or directory
            $isFile = $item.Type -eq 'File'
            $rowClass = if ($isFile) { "tree-row file" } else { "tree-row" }
            $icon = if ($isFile) { "📄" } else { "📁" }
            $iconClass = if ($isFile) { "file-icon" } else { "folder-icon" }
            
            # Build indent guides
            $indentHtml = ""
            for ($i = 0; $i -lt $level; $i++) {
                $indentHtml += '<div class="indent-guide"></div>'
            }
            
            # Determine if we need a toggle button (has children and is a directory)
            $showToggle = $hasChildren.ContainsKey($path) -and -not $isFile
            $toggleHtml = if ($showToggle) {
                '<button class="toggle-btn" onclick="toggleFolder(this, event)">▶</button>'
            } else {
                '<span class="toggle-placeholder"></span>'
            }
            
            # Hide non-root rows by default (collapsed state)
            $hiddenClass = if ($level -gt 0) { " hidden" } else { "" }
            
            $rows += @"
                    <div class="$rowClass$hiddenClass" data-level="$level" data-path="$escapedPath" data-parent="$escapedParent" data-computer="$ComputerIndex">
                        <div class="tree-name">
                            <div class="tree-indent">
                                $indentHtml
                                $toggleHtml
                            </div>
                            <span class="item-icon $iconClass">$icon</span>
                            <span class="item-label" title="$escapedPath">$escapedName</span>
                        </div>
                        <span class="tree-percent">$percentage%</span>
                        <span class="tree-size">$($item.SizeFormatted)</span>
                        <div class="tree-bar"><div class="tree-bar-fill $barClass" style="width: $percentage%"></div></div>
                    </div>
"@
        }
        
        return $rows
    }
    
    # Build computer sections
    $computerSections = ""
    $computerIndex = 0
    $headerColors = @("", "server2", "server3", "server4", "server5")
    
    foreach ($group in $computerGroups) {
        $computerName = $group.Name
        $computerItems = $group.Group
        
        $dirs = $computerItems | Where-Object { $_.Type -eq 'Directory' }
        $files = $computerItems | Where-Object { $_.Type -eq 'File' }
        
        $rootSize = if ($dirs.Count -gt 0) { ($dirs | Select-Object -First 1).Size } else { 0 }
        $rootSizeFormatted = Format-FileSize $rootSize
        
        # Get scan time for this computer
        $compScanTime = if ($computerItems.Count -gt 0) { $computerItems[0].ScanTime } else { [timespan]::Zero }
        $compScanTimeFormatted = "{0:mm\:ss\.fff}" -f $compScanTime
        $compScanEnd = if ($computerItems.Count -gt 0) { $computerItems[0].ScanDateEnd.ToString('HH:mm:ss') } else { "" }
        
        $headerColorClass = $headerColors[$computerIndex % $headerColors.Count]
        
        # Combine directories and files for tree view
        $allItems = @()
        $allItems += $dirs
        $allItems += $files
        
        $treeRows = Build-TreeRows -Items $allItems -RootSize $rootSize -ComputerIndex $computerIndex
        
        $computerSections += @"
        <div class="computer-section">
            <div class="computer-header $headerColorClass" onclick="toggleComputer(this)">
                <div class="computer-info">
                    <button class="computer-toggle expanded">▶</button>
                    <span class="computer-icon">🖥️</span>
                    <span class="computer-name">$computerName</span>
                    <span class="computer-drive">${DriveLetter}:\</span>
                    <span class="status-badge status-online">✓ Scanned</span>
                </div>
                <div class="computer-stats">
                    <div class="computer-stat">
                        <span class="computer-stat-label">Total Size</span>
                        <span class="computer-stat-value size">$rootSizeFormatted</span>
                    </div>
                    <div class="computer-stat">
                        <span class="computer-stat-label">Scan Time</span>
                        <span class="computer-stat-value time">$compScanTimeFormatted</span>
                    </div>
                    <div class="computer-stat">
                        <span class="computer-stat-label">Completed</span>
                        <span class="computer-stat-value">$compScanEnd</span>
                    </div>
                </div>
            </div>
            <div class="tree-container">
                <div class="tree-header">
                    <span>Name</span>
                    <span>Percent</span>
                    <span>Size</span>
                    <span>Size Graph</span>
                </div>
                <div class="tree-body">
$treeRows
                </div>
            </div>
        </div>
"@
        $computerIndex++
    }
    
    # Main header content
    $mainHeaderTitle = if ($isMultiComputer) {
        "Multi-Computer Disk Analysis"
    } else {
        "Disk Space Analysis"
    }
    
    $mainHeaderSubtitle = if ($isMultiComputer) {
        "Drive ${DriveLetter}:\ across $($computerGroups.Count) servers"
    } else {
        "Drive ${DriveLetter}:\ on $($computerGroups[0].Name)"
    }
    
    $mainStatsHtml = if ($isMultiComputer) {
        @"
            <div class="main-stats">
                <div class="main-stat">
                    <div class="main-stat-value">$($computerGroups.Count)</div>
                    <div class="main-stat-label">Computers</div>
                </div>
                <div class="main-stat">
                    <div class="main-stat-value">$totalSizeAllFormatted</div>
                    <div class="main-stat-label">Total Analyzed</div>
                </div>
                <div class="main-stat">
                    <div class="main-stat-value">$scanTimeFormatted</div>
                    <div class="main-stat-label">Total Duration</div>
                </div>
            </div>
"@
    } else {
        @"
            <div class="main-stats">
                <div class="main-stat">
                    <div class="main-stat-value">$totalSizeAllFormatted</div>
                    <div class="main-stat-label">Total Size</div>
                </div>
                <div class="main-stat">
                    <div class="main-stat-value">$($ScanDateStart.ToString('HH:mm:ss'))</div>
                    <div class="main-stat-label">Started</div>
                </div>
                <div class="main-stat">
                    <div class="main-stat-value">$($ScanDateEnd.ToString('HH:mm:ss'))</div>
                    <div class="main-stat-label">Completed</div>
                </div>
                <div class="main-stat">
                    <div class="main-stat-value">$scanTimeFormatted</div>
                    <div class="main-stat-label">Duration</div>
                </div>
            </div>
"@
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$mainHeaderTitle - ${DriveLetter}:\</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Segoe+UI:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #1e1e2e;
            --bg-secondary: #282839;
            --bg-hover: #313244;
            --bg-selected: #3d3d54;
            --text-primary: #cdd6f4;
            --text-secondary: #a6adc8;
            --text-muted: #6c7086;
            --border-color: #45475a;
            --accent-blue: #89b4fa;
            --accent-green: #a6e3a1;
            --accent-yellow: #f9e2af;
            --accent-peach: #fab387;
            --accent-red: #f38ba8;
            --accent-mauve: #cba6f7;
            --accent-teal: #94e2d5;
            --folder-yellow: #f9e2af;
            --file-blue: #89b4fa;
            --bar-bg: #45475a;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.4;
            font-size: 14px;
        }

        .container { max-width: 1600px; margin: 0 auto; padding: 1rem; }

        .main-header {
            background: linear-gradient(135deg, #313244 0%, #282839 100%);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .main-header-title { display: flex; align-items: center; gap: 0.75rem; }
        .main-header-title .icon { font-size: 1.75rem; }
        .main-header-title h1 { font-size: 1.35rem; font-weight: 600; color: var(--text-primary); }
        .main-header-title .subtitle { font-size: 0.85rem; color: var(--text-muted); margin-top: 0.125rem; }

        .main-stats { display: flex; gap: 2rem; flex-wrap: wrap; }
        .main-stat { text-align: center; }
        .main-stat-value { font-family: 'JetBrains Mono', monospace; font-size: 1.5rem; font-weight: 600; color: var(--accent-blue); }
        .main-stat-label { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

        .computer-section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }

        .computer-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem 1.25rem;
            background: linear-gradient(90deg, rgba(137, 180, 250, 0.1) 0%, transparent 100%);
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            transition: background 0.2s ease;
        }

        .computer-header:hover { background: linear-gradient(90deg, rgba(137, 180, 250, 0.15) 0%, rgba(137, 180, 250, 0.05) 100%); }
        .computer-header.server2 { background: linear-gradient(90deg, rgba(166, 227, 161, 0.1) 0%, transparent 100%); }
        .computer-header.server2:hover { background: linear-gradient(90deg, rgba(166, 227, 161, 0.15) 0%, rgba(166, 227, 161, 0.05) 100%); }
        .computer-header.server3 { background: linear-gradient(90deg, rgba(249, 226, 175, 0.1) 0%, transparent 100%); }
        .computer-header.server3:hover { background: linear-gradient(90deg, rgba(249, 226, 175, 0.15) 0%, rgba(249, 226, 175, 0.05) 100%); }
        .computer-header.server4 { background: linear-gradient(90deg, rgba(203, 166, 247, 0.1) 0%, transparent 100%); }
        .computer-header.server4:hover { background: linear-gradient(90deg, rgba(203, 166, 247, 0.15) 0%, rgba(203, 166, 247, 0.05) 100%); }
        .computer-header.server5 { background: linear-gradient(90deg, rgba(148, 226, 213, 0.1) 0%, transparent 100%); }
        .computer-header.server5:hover { background: linear-gradient(90deg, rgba(148, 226, 213, 0.15) 0%, rgba(148, 226, 213, 0.05) 100%); }

        .computer-info { display: flex; align-items: center; gap: 1rem; }

        .computer-toggle {
            width: 24px; height: 24px;
            display: flex; align-items: center; justify-content: center;
            background: none; border: none;
            color: var(--text-muted); cursor: pointer;
            border-radius: 4px; font-size: 0.8rem;
            transition: all 0.15s ease;
        }
        .computer-toggle:hover { background: var(--bg-hover); color: var(--text-primary); }
        .computer-toggle.expanded { transform: rotate(90deg); }

        .computer-icon { font-size: 1.5rem; }
        .computer-name { font-weight: 600; font-size: 1.1rem; color: var(--text-primary); }
        .computer-drive {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem; color: var(--accent-blue);
            background: rgba(137, 180, 250, 0.15);
            padding: 0.25rem 0.5rem; border-radius: 4px;
        }

        .computer-stats { display: flex; gap: 1.5rem; align-items: center; }
        .computer-stat { display: flex; flex-direction: column; align-items: flex-end; gap: 0.125rem; }
        .computer-stat-label { font-size: 0.65rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
        .computer-stat-value { font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: var(--text-primary); font-weight: 500; }
        .computer-stat-value.size { color: var(--accent-blue); font-size: 1rem; }
        .computer-stat-value.time { color: var(--accent-green); }

        .tree-container { overflow: hidden; }
        .tree-container.collapsed { display: none; }

        .tree-header {
            display: grid;
            grid-template-columns: 1fr 100px 140px 200px;
            gap: 1rem;
            padding: 0.6rem 1rem;
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            font-size: 0.7rem; font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .tree-header span:nth-child(2), .tree-header span:nth-child(3) { text-align: right; }

        .tree-body { max-height: 500px; overflow-y: auto; }

        .tree-row {
            display: grid;
            grid-template-columns: 1fr 100px 140px 200px;
            gap: 1rem;
            padding: 0.45rem 1rem;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            transition: background 0.15s ease;
            align-items: center;
        }
        .tree-row:hover { background: var(--bg-hover); }
        .tree-row:last-child { border-bottom: none; }
        .tree-row.selected { background: var(--bg-selected); }
        .tree-row.hidden { display: none; }
        .tree-row.file { background: rgba(0,0,0,0.1); }
        .tree-row.file:hover { background: var(--bg-hover); }

        .tree-name { display: flex; align-items: center; gap: 0.5rem; min-width: 0; }
        .tree-indent { display: flex; align-items: center; flex-shrink: 0; }

        .indent-guide {
            width: 20px; height: 100%;
            position: relative; flex-shrink: 0;
        }
        .indent-guide::before {
            content: '';
            position: absolute; left: 9px; top: 0; bottom: 0;
            width: 1px; background: var(--border-color);
        }

        .toggle-btn {
            width: 18px; height: 18px;
            display: flex; align-items: center; justify-content: center;
            background: none; border: none;
            color: var(--text-muted); cursor: pointer;
            border-radius: 4px; flex-shrink: 0;
            font-size: 0.65rem;
            transition: all 0.15s ease;
        }
        .toggle-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
        .toggle-btn.expanded { transform: rotate(90deg); }
        .toggle-placeholder { width: 18px; flex-shrink: 0; }

        .item-icon { font-size: 0.95rem; flex-shrink: 0; }
        .folder-icon { color: var(--folder-yellow); }
        .file-icon { color: var(--file-blue); }

        .item-label {
            white-space: nowrap; overflow: hidden;
            text-overflow: ellipsis;
            color: var(--text-primary); font-size: 0.9rem;
        }
        .tree-row.file .item-label { color: var(--text-secondary); }

        .tree-percent { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; text-align: right; color: var(--text-secondary); }
        .tree-size { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; text-align: right; color: var(--text-primary); font-weight: 500; }

        .tree-bar { height: 16px; background: var(--bar-bg); border-radius: 3px; overflow: hidden; }
        .tree-bar-fill { height: 100%; border-radius: 3px; transition: width 0.3s ease; }
        .tree-row.file .tree-bar-fill { background: linear-gradient(90deg, var(--accent-mauve), var(--accent-blue)); opacity: 0.7; }

        .bar-100 { background: linear-gradient(90deg, #89b4fa, #b4befe); }
        .bar-90 { background: linear-gradient(90deg, #94e2d5, #89dceb); }
        .bar-80 { background: linear-gradient(90deg, #a6e3a1, #94e2d5); }
        .bar-70 { background: linear-gradient(90deg, #f9e2af, #a6e3a1); }
        .bar-60 { background: linear-gradient(90deg, #fab387, #f9e2af); }
        .bar-50 { background: linear-gradient(90deg, #eba0ac, #fab387); }
        .bar-40 { background: linear-gradient(90deg, #f38ba8, #eba0ac); }
        .bar-30 { background: linear-gradient(90deg, #cba6f7, #f38ba8); }
        .bar-20 { background: linear-gradient(90deg, #b4befe, #cba6f7); }
        .bar-10 { background: linear-gradient(90deg, #89b4fa, #b4befe); }

        .status-badge {
            font-size: 0.65rem; padding: 0.2rem 0.5rem;
            border-radius: 4px; font-weight: 500;
            text-transform: uppercase; letter-spacing: 0.03em;
        }
        .status-online { background: rgba(166, 227, 161, 0.2); color: var(--accent-green); }

        .footer { text-align: center; padding: 1rem; color: var(--text-muted); font-size: 0.8rem; }

        .tree-body::-webkit-scrollbar { width: 8px; }
        .tree-body::-webkit-scrollbar-track { background: var(--bg-primary); }
        .tree-body::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 4px; }
        .tree-body::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

        @media (max-width: 1000px) {
            .tree-header, .tree-row { grid-template-columns: 1fr 80px 100px; }
            .tree-header span:nth-child(4), .tree-row .tree-bar { display: none; }
            .computer-stats { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="main-header">
            <div class="main-header-title">
                <span class="icon">🖥️</span>
                <div>
                    <h1>$mainHeaderTitle</h1>
                    <div class="subtitle">$mainHeaderSubtitle</div>
                </div>
            </div>
$mainStatsHtml
        </div>

$computerSections

        <div class="footer">
            Generated by <strong>DiskSpaceAnalyzer</strong> PowerShell Module • $($ScanDateEnd.ToString('yyyy-MM-dd HH:mm:ss'))
        </div>
    </div>

    <script>
        function toggleComputer(header) {
            const toggle = header.querySelector('.computer-toggle');
            const treeContainer = header.nextElementSibling;
            toggle.classList.toggle('expanded');
            treeContainer.classList.toggle('collapsed');
        }

        function toggleFolder(btn, event) {
            event.stopPropagation();
            const row = btn.closest('.tree-row');
            const path = row.dataset.path;
            const computer = row.dataset.computer;
            const isExpanded = btn.classList.contains('expanded');
            btn.classList.toggle('expanded');

            const allRows = row.closest('.tree-body').querySelectorAll('.tree-row');
            allRows.forEach(r => {
                const parent = r.dataset.parent;
                if (parent && parent.startsWith(path) && r !== row && r.dataset.computer === computer) {
                    if (isExpanded) {
                        r.classList.add('hidden');
                        const childBtn = r.querySelector('.toggle-btn');
                        if (childBtn) childBtn.classList.remove('expanded');
                    } else {
                        if (r.dataset.parent === path) {
                            r.classList.remove('hidden');
                        }
                    }
                }
            });
        }

        document.querySelectorAll('.tree-row').forEach(row => {
            row.addEventListener('click', (e) => {
                if (e.target.closest('.toggle-btn')) return;
                document.querySelectorAll('.tree-row').forEach(r => r.classList.remove('selected'));
                row.classList.add('selected');
            });
        });
    </script>
</body>
</html>
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

    .PARAMETER ExportHtml
        Export results to a beautiful HTML report. Specify the output file path.

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
        Get-DiskSpaceUsage -DriveLetter D -ExportHtml "C:\Reports\DiskUsage.html"
        
        Analyzes the D: drive and exports results to a beautiful HTML report.

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
        - ScanDateStart: When the scan started
        - ScanDateEnd: When the scan completed
        - ScanTime: Duration of the scan (TimeSpan)

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
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter()]
        [string]$ExportHtml
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
            $scanDateStart = Get-Date
            $reader = New-Object MftReader($DriveLetter)
            $reader.ReadMft($null)
            $reader.CalculateDirectorySizes()
            $scanDateEnd = Get-Date
            $scanTime = $scanDateEnd - $scanDateStart

            $results = @()
            $computerName = $env:COMPUTERNAME

            # Get largest directories
            $dirs = $reader.GetLargestDirectories($TopCount)
            $rank = 1
            foreach ($dir in $dirs) {
                $results += [PSCustomObject]@{
                    ComputerName   = $computerName
                    Rank           = $rank
                    Path           = $dir.FullPath
                    Size           = $dir.Size
                    SizeFormatted  = if ($dir.Size -ge 1TB) { "{0:F2} TB" -f ($dir.Size / 1TB) }
                                    elseif ($dir.Size -ge 1GB) { "{0:F2} GB" -f ($dir.Size / 1GB) }
                                    elseif ($dir.Size -ge 1MB) { "{0:F2} MB" -f ($dir.Size / 1MB) }
                                    elseif ($dir.Size -ge 1KB) { "{0:F2} KB" -f ($dir.Size / 1KB) }
                                    else { "$($dir.Size) B" }
                    SizeKB         = [math]::Round($dir.Size / 1KB, 2)
                    SizeMB         = [math]::Round($dir.Size / 1MB, 2)
                    SizeGB         = [math]::Round($dir.Size / 1GB, 2)
                    Type           = 'Directory'
                    ScanDateStart  = $scanDateStart
                    ScanDateEnd    = $scanDateEnd
                    ScanTime       = $scanTime
                }
                $rank++
            }

            # Get largest files if requested
            if ($IncludeFiles) {
                $files = $reader.GetLargestFiles($TopCount)
                $rank = 1
                foreach ($file in $files) {
                    $results += [PSCustomObject]@{
                        ComputerName   = $computerName
                        Rank           = $rank
                        Path           = $file.FullPath
                        Size           = $file.Size
                        SizeFormatted  = if ($file.Size -ge 1TB) { "{0:F2} TB" -f ($file.Size / 1TB) }
                                        elseif ($file.Size -ge 1GB) { "{0:F2} GB" -f ($file.Size / 1GB) }
                                        elseif ($file.Size -ge 1MB) { "{0:F2} MB" -f ($file.Size / 1MB) }
                                        elseif ($file.Size -ge 1KB) { "{0:F2} KB" -f ($file.Size / 1KB) }
                                        else { "$($file.Size) B" }
                        SizeKB         = [math]::Round($file.Size / 1KB, 2)
                        SizeMB         = [math]::Round($file.Size / 1MB, 2)
                        SizeGB         = [math]::Round($file.Size / 1GB, 2)
                        Type           = 'File'
                        ScanDateStart  = $scanDateStart
                        ScanDateEnd    = $scanDateEnd
                        ScanTime       = $scanTime
                    }
                    $rank++
                }
            }

            return $results
        }

        # Collect all computer names from pipeline
        $allComputers = [System.Collections.Generic.List[string]]::new()
        
        # Collect all results for HTML export
        $allResults = [System.Collections.Generic.List[object]]::new()
        $scanStartTime = $null
        $scanEndTime = $null
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
                
                $scanDateStart = Get-Date
                Write-Verbose "Reading MFT from drive $($DriveLetter):\..."
                $reader.ReadMft($null)
                
                Write-Verbose "MFT read complete: $($reader.RecordCount.ToString('N0')) records"
                Write-Verbose "Calculating directory sizes..."
                $reader.CalculateDirectorySizes()
                $scanDateEnd = Get-Date
                $scanTime = $scanDateEnd - $scanDateStart
                
                $computerName = $env:COMPUTERNAME

                # Get largest directories
                $dirs = $reader.GetLargestDirectories($TopCount)
                $rank = 1
                foreach ($dir in $dirs) {
                    $result = [PSCustomObject]@{
                        ComputerName   = $computerName
                        Rank           = $rank
                        Path           = $dir.FullPath
                        Size           = $dir.Size
                        SizeFormatted  = Format-FileSize $dir.Size
                        SizeKB         = [math]::Round($dir.Size / 1KB, 2)
                        SizeMB         = [math]::Round($dir.Size / 1MB, 2)
                        SizeGB         = [math]::Round($dir.Size / 1GB, 2)
                        Type           = 'Directory'
                        ScanDateStart  = $scanDateStart
                        ScanDateEnd    = $scanDateEnd
                        ScanTime       = $scanTime
                    }
                    $allResults.Add($result)
                    $result
                    $rank++
                }

                # Get largest files if requested
                if ($IncludeFiles) {
                    $files = $reader.GetLargestFiles($TopCount)
                    $rank = 1
                    foreach ($file in $files) {
                        $result = [PSCustomObject]@{
                            ComputerName   = $computerName
                            Rank           = $rank
                            Path           = $file.FullPath
                            Size           = $file.Size
                            SizeFormatted  = Format-FileSize $file.Size
                            SizeKB         = [math]::Round($file.Size / 1KB, 2)
                            SizeMB         = [math]::Round($file.Size / 1MB, 2)
                            SizeGB         = [math]::Round($file.Size / 1GB, 2)
                            Type           = 'File'
                            ScanDateStart  = $scanDateStart
                            ScanDateEnd    = $scanDateEnd
                            ScanTime       = $scanTime
                        }
                        $allResults.Add($result)
                        $result
                        $rank++
                    }
                }
                
                $scanStartTime = $scanDateStart
                $scanEndTime = $scanDateEnd
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
                        $outputResult = [PSCustomObject]@{
                            ComputerName   = $result.ComputerName
                            Rank           = $result.Rank
                            Path           = $result.Path
                            Size           = $result.Size
                            SizeFormatted  = $result.SizeFormatted
                            SizeKB         = $result.SizeKB
                            SizeMB         = $result.SizeMB
                            SizeGB         = $result.SizeGB
                            Type           = $result.Type
                            ScanDateStart  = $result.ScanDateStart
                            ScanDateEnd    = $result.ScanDateEnd
                            ScanTime       = $result.ScanTime
                        }
                        $allResults.Add($outputResult)
                        $outputResult
                        
                        # Track scan times
                        if ($null -eq $scanStartTime -or $result.ScanDateStart -lt $scanStartTime) {
                            $scanStartTime = $result.ScanDateStart
                        }
                        if ($null -eq $scanEndTime -or $result.ScanDateEnd -gt $scanEndTime) {
                            $scanEndTime = $result.ScanDateEnd
                        }
                    }
                }
                catch {
                    Write-Error "Error analyzing $computer`: $_"
                }
            }
        }
        
        # Export to HTML if requested
        if ($ExportHtml -and $allResults.Count -gt 0) {
            $totalScanTime = if ($scanStartTime -and $scanEndTime) { $scanEndTime - $scanStartTime } else { [timespan]::Zero }
            
            Export-DiskSpaceHtml -Results $allResults `
                                 -OutputPath $ExportHtml `
                                 -DriveLetter $DriveLetter `
                                 -ScanDateStart $scanStartTime `
                                 -ScanDateEnd $scanEndTime `
                                 -ScanTime $totalScanTime
            
            Write-Host "HTML report exported to: $ExportHtml" -ForegroundColor Green
        }
    }
}

#endregion

# Export the function
Export-ModuleMember -Function Get-DiskSpaceUsage
