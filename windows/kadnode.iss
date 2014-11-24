; Project file for Inno Setup to create a KadNode installer

[Setup]
AppName=KadNode
AppVersion="0.9.2"
AppPublisher="Moritz Warning"
AppPublisherURL="https://github.com/mwarning/KadNode"
DefaultDirName={pf}\KadNode
DefaultGroupName=KadNode
PrivilegesRequired=admin
AllowNoIcons=yes
LicenseFile=..\LICENSE
OutputDir=..\build
OutputBaseFilename=kadnode_setup
Compression=lzma
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "C:\cygwin64\bin\cygwin1.dll"; DestDir: "{app}"
Source: "..\build\kadnode.exe"; DestDir: "{app}"
Source: "..\build\kadnode-ctl.exe"; DestDir: "{app}"
Source: "..\windows\kadnode-start.bat"; DestDir: "{app}"
Source: "..\windows\config.txt"; DestDir: "{app}"
Source: "..\README.md"; DestDir: "{app}"; DestName: "readme.txt"; Flags: isreadme; AfterInstall: ConvertLineEndings 
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "license.txt"; AfterInstall: ConvertLineEndings
Source: "..\debian\peers.txt"; DestDir: "{app}"; AfterInstall: ConvertLineEndings
Source: "..\debian\changelog"; DestDir: "{app}"; DestName: "changelog.txt"; AfterInstall: ConvertLineEndings

[Icons]
Name: "{group}\Configuration"; Filename: "{app}\config.txt"
Name: "{group}\ReadMe"; Filename: "{app}\readme.txt"
Name: "{group}\{cm:UninstallProgram,KadNode}"; Filename: "{uninstallexe}"
;Create a link from the autostart folder to the startup script.
Name: "{commonstartup}\kadnode"; Filename: "{app}\kadnode.bat"

[Run]
Filename: "{sys}\schtasks.exe"; Parameters: "/Create /F /TN KadNode /RU ""NT AUTHORITY\NETWORKSERVICE"" /SC ONSTART /TR ""'{app}\kadnode-start.bat'"" /NP /RL HIGHEST"
Filename: "{app}\kadnode-bat.bat"; Description: {cm:LaunchMsg}; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN KadNode"
Filename: "{sys}\taskkill.exe"; Parameters: "/f /im kadnode.exe"; Flags: skipifdoesntexist runhidden

[CustomMessages]
LaunchMsg=Start KadNode now

[Code]
const
  LF = #10;
  CR = #13;
  CRLF = CR + LF;

procedure ConvertLineEndings();
var
  FilePath : String;
  FileContents : String;
begin
  FilePath := ExpandConstant(CurrentFileName)
  LoadStringFromFile(FilePath, FileContents);
  StringChangeEx(FileContents, LF, CRLF, False);
  SaveStringToFile(FilePath, FileContents, False);
end;
