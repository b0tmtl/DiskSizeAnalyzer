# DiskSizeAnalyzer

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/DiskSizeAnalyzer?label=PowerShell%20Gallery&logo=powershell)](https://www.powershellgallery.com/packages/DiskSizeAnalyzer)
[![License](https://img.shields.io/badge/License-PolyForm%20Noncommercial-blue.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)

**Blazingly fast disk space analyzer for Windows using direct MFT (Master File Table) reading.**

Analyze entire drives in seconds, not minutes. DiskSizeAnalyzer bypasses the slow Windows file system APIs by reading the NTFS Master File Table directly, providing near-instant results for even the largest drives.

## ✨ Features

- **Lightning Fast** — Analyzes entire drives in seconds by reading the MFT directly
- **No Dependencies** — Pure PowerShell module with embedded C#, no external tools required
- **PowerShell Objects** — Returns proper objects for easy filtering, sorting, and exporting
- **Remote Support** — Analyze remote computers with `-ComputerName` and `-Credential`
- **Pipeline Friendly** — Works seamlessly with PowerShell pipeline and other cmdlets
- **Export Ready** — Easily export results to CSV, JSON, or any format

## 📊 Performance Comparison

| Method | 1TB Drive | 4TB Drive |
|--------|-----------|-----------|
| Windows Explorer | 5-15 min | 20-60 min |
| TreeSize/WinDirStat | 2-8 min | 10-30 min |
| **DiskSizeAnalyzer** | **5-15 sec** | **15-45 sec** |

## 🚀 Installation

### From PowerShell Gallery (Recommended)

```powershell
Install-Module -Name DiskSizeAnalyzer
```

### Manual Installation

1. Download the latest release from [GitHub Releases](https://github.com/YOUR_USERNAME/DiskSizeAnalyzer/releases)
2. Extract to a PowerShell module path:
   ```powershell
   # Check your module paths
   $env:PSModulePath -split ';'
   
   # Common location
   # C:\Users\<YourName>\Documents\PowerShell\Modules\DiskSizeAnalyzer
   ```
3. Import the module:
   ```powershell
   Import-Module DiskSizeAnalyzer
   ```

## 📖 Usage

### Basic Usage

```powershell
# Analyze C: drive (default)
Get-DiskSpaceUsage

# Analyze a different drive
Get-DiskSpaceUsage -DriveLetter D

# Get more results
Get-DiskSpaceUsage -TopCount 50

# Include largest files (not just directories)
Get-DiskSpaceUsage -IncludeFiles
```

### Remote Computers

```powershell
# Single remote computer
Get-DiskSpaceUsage -ComputerName "Server01"

# Multiple remote computers
Get-DiskSpaceUsage -ComputerName "Server01", "Server02", "Server03"

# With credentials
Get-DiskSpaceUsage -ComputerName "Server01" -Credential (Get-Credential)

# Pipeline input
"Server01", "Server02" | Get-DiskSpaceUsage -DriveLetter D
```

### Filtering and Exporting

```powershell
# Find directories larger than 10 GB
Get-DiskSpaceUsage | Where-Object { $_.SizeGB -gt 10 }

# Export to CSV
Get-DiskSpaceUsage -IncludeFiles | Export-Csv -Path "DiskUsage.csv" -NoTypeInformation

# Export to JSON
Get-DiskSpaceUsage | ConvertTo-Json | Out-File "DiskUsage.json"

# Sort by size
Get-DiskSpaceUsage -TopCount 100 | Sort-Object Size -Descending

# Group by type
Get-DiskSpaceUsage -IncludeFiles | Group-Object Type

# Get only directories in a specific path
Get-DiskSpaceUsage | Where-Object { $_.Path -like "C:\Users\*" }
```

### Real-World Examples

```powershell
# Find what's eating your disk space
Get-DiskSpaceUsage -TopCount 20 | Format-Table Rank, SizeFormatted, Path

# Audit multiple servers
$servers = "DC01", "FS01", "SQL01"
$servers | Get-DiskSpaceUsage | Export-Csv "ServerDiskAudit.csv" -NoTypeInformation

# Find large files for cleanup
Get-DiskSpaceUsage -IncludeFiles | 
    Where-Object { $_.Type -eq 'File' -and $_.SizeGB -gt 1 } |
    Select-Object Path, SizeFormatted

# Compare disk usage across servers
$results = "Server01", "Server02" | Get-DiskSpaceUsage
$results | Group-Object ComputerName | ForEach-Object {
    [PSCustomObject]@{
        Server = $_.Name
        TotalAnalyzed = ($_.Group | Measure-Object Size -Sum).Sum / 1GB
    }
}
```

## 📋 Output Properties

| Property | Type | Description |
|----------|------|-------------|
| `ComputerName` | String | Name of the analyzed computer |
| `Rank` | Int | Size ranking (1 = largest) |
| `Path` | String | Full path to the directory or file |
| `Size` | Long | Size in bytes |
| `SizeFormatted` | String | Human-readable size (e.g., "5.23 GB") |
| `SizeKB` | Double | Size in kilobytes |
| `SizeMB` | Double | Size in megabytes |
| `SizeGB` | Double | Size in gigabytes |
| `Type` | String | "Directory" or "File" |
| `ScanDate` | DateTime | When the scan was performed |

## ⚙️ Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-DriveLetter` | String | `C` | Drive letter to analyze (without colon) |
| `-TopCount` | Int | `30` | Number of results to return (1-1000) |
| `-IncludeFiles` | Switch | `$false` | Include largest files in output |
| `-ComputerName` | String[] | Local | Target computer(s) to analyze |
| `-Credential` | PSCredential | Current | Credentials for remote connections |

## ⚠️ Requirements

- **Windows PowerShell 5.1** or **PowerShell 7+**
- **Administrator privileges** (required for raw disk access)
- **NTFS formatted drives** (MFT is NTFS-specific)
- **PowerShell Remoting** enabled on remote targets (for `-ComputerName`)

## 🔧 How It Works

Traditional disk analyzers use Windows file system APIs to enumerate files, which requires traversing the entire directory tree — a slow process for large drives.

DiskSizeAnalyzer takes a different approach:

1. Opens the volume with raw disk access
2. Reads the NTFS Master File Table (MFT) directly
3. Parses file records to extract sizes and parent-child relationships
4. Calculates cumulative directory sizes using an efficient bottom-up algorithm

This approach reads a single contiguous data structure instead of millions of scattered file system calls, resulting in dramatically faster analysis.

## 🐛 Troubleshooting

### "Administrator privileges required"
Run PowerShell as Administrator. Raw disk access requires elevated privileges.

### "Failed to open volume"
- Ensure the drive exists and is NTFS formatted
- Check that no other application has exclusive access to the volume

### Remote connection fails
- Verify PowerShell Remoting is enabled: `Enable-PSRemoting -Force`
- Check firewall allows WinRM (TCP 5985/5986)
- Verify credentials have admin rights on the target

### Results seem incomplete
- System files (starting with `$`) are filtered out by design
- Deleted files are excluded
- Some files may have invalid MFT records

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the **PolyForm Noncommercial License 1.0.0** — you are free to use, modify, and distribute this software for any noncommercial purpose. See the [LICENSE](LICENSE) file for details.

**In short:** ✅ Free to use ✅ Free to modify ✅ Free to share ❌ Cannot be sold

## 🙏 Acknowledgments

- Inspired by tools like WinDirStat, TreeSize, and WizTree
- Built with embedded C# for maximum performance
- Thanks to the PowerShell community for feedback and testing

---

**⭐ If you find this useful, please consider giving it a star on GitHub!**
