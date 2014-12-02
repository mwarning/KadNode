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
Source: "..\windows\kadnode-stop.bat"; DestDir: "{app}"
Source: "..\windows\config.txt"; DestDir: "{app}"
Source: "..\README.md"; DestDir: "{app}"; DestName: "readme.txt"; AfterInstall: ConvertLineEndings 
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "license.txt"; AfterInstall: ConvertLineEndings
Source: "..\debian\peers.txt"; DestDir: "{app}"; AfterInstall: ConvertLineEndings
Source: "..\debian\changelog"; DestDir: "{app}"; DestName: "changelog.txt"; AfterInstall: ConvertLineEndings

[Icons]
Name: "{group}\Configuration"; Filename: "{app}\config.txt"
Name: "{group}\ReadMe"; Filename: "{app}\readme.txt"
Name: "{group}\kadnode-start"; Filename: "{app}\kadnode-start.bat"
Name: "{group}\kadnode-stop"; Filename: "{app}\kadnode-stop.bat"
Name: "{group}\{cm:UninstallProgram,KadNode}"; Filename: "{uninstallexe}"

[Run]
Filename: "{sys}\schtasks.exe"; Parameters: "/Create /F /TN KadNode /RU ""NT AUTHORITY\NETWORKSERVICE"" /SC ONSTART /TR ""'{app}\kadnode-start.bat'"" /NP /RL HIGHEST"; Flags: runhidden
Filename: "{app}\readme.txt"; Flags: shellexec skipifdoesntexist postinstall skipifsilent
Filename: "{app}\kadnode-start.bat"; Description: {cm:LaunchMsg}; Flags: nowait postinstall skipifsilent runascurrentuser runhidden

[UninstallRun]
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN KadNode"; Flags: runhidden
Filename: "{app}\kadnode-stop.bat"; Flags: runhidden

[CustomMessages]
LaunchMsg=Start KadNode now

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nKadNode is a dezentralized DNS system based on a distributed hash table.%n%nBe aware that this package is in an alpha stage and will change your DNS settings.

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
