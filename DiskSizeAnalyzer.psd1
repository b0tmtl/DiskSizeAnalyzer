@{
    # Module manifest for DiskSizeAnalyzer

    # Script module file associated with this manifest
    RootModule = 'DiskSizeAnalyzer.psm1'

    # Version number of this module
    ModuleVersion = '1.1.2'

    # ID used to uniquely identify this module
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'

    # Author of this module
    Author = 'b0tmtl'

    # Copyright statement for this module
    Copyright = '(c) 2025. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Fast disk space analyzer using MFT (Master File Table) reading. Analyzes NTFS drives and returns the largest directories and files as PowerShell objects. Supports local and remote computer analysis.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @('Get-DiskSpaceUsage')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            Tags = @('Disk', 'Storage', 'MFT', 'NTFS', 'Analysis', 'Space')
            LicenseUri = 'https://github.com/b0tmtl/DiskSizeAnalyzer/blob/main/LICENSE'
            ProjectUri = 'https://github.com/b0tmtl/DiskSizeAnalyzer'
            ReleaseNotes = 'Initial release with remote computer support'
        }
    }
}
