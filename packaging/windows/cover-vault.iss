#define MyAppName "Cover Vault"
#define MyAppVersion GetEnv("COVER_VAULT_VERSION")
#if MyAppVersion == ""
  #define MyAppVersion "2.1.0"
#endif
#define MyAppPublisher "Cover Vault"
#define MyAppExeName "CoverVault.exe"

[Setup]
AppId={{2BC09DD8-CC84-4C7C-92EA-C60A4D51516F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Cover Vault
DefaultGroupName=Cover Vault
DisableProgramGroupPage=yes
OutputDir=..\..\dist\installer
OutputBaseFilename=CoverVault-{#MyAppVersion}-Windows-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
Source: "..\..\dist\CoverVault\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Cover Vault"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Cover Vault"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Cover Vault"; Flags: nowait postinstall skipifsilent
