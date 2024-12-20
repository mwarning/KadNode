; Project file for Inno Setup to create a KadNode installer

[Setup]
AppName=KadNode
AppVersion="2.4.0"
AppPublisher="Moritz Warning"
AppPublisherURL="https://github.com/mwarning/KadNode"
DefaultDirName={pf}\KadNode
DefaultGroupName=KadNode
PrivilegesRequired=admin
AllowNoIcons=yes
LicenseFile=..\LICENSE
OutputDir=..\build
OutputBaseFilename=kadnode_2.4.0_amd64
Compression=lzma
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "C:\cygwin64\bin\cygwin1.dll"; DestDir: "{app}"
Source: "C:\cygwin64\bin\cyggcc_s-seh-1.dll"; DestDir: "{app}"
Source: "..\build\kadnode.exe"; DestDir: "{app}"
Source: "..\build\kadnode-ctl.exe"; DestDir: "{app}"
Source: "..\windows\dns_setup.bat"; DestDir: "{app}"
Source: "..\windows\dns_reset.bat"; DestDir: "{app}"
Source: "..\windows\kadnode_start.bat"; DestDir: "{app}"
Source: "..\windows\kadnode_stop.bat"; DestDir: "{app}"
Source: "..\misc\kadnode.conf"; DestDir: "{app}"; AfterInstall: ConvertLineEndings
Source: "..\README.md"; DestDir: "{app}"; DestName: "readme.txt"; AfterInstall: ConvertLineEndings 
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "license.txt"; AfterInstall: ConvertLineEndings
Source: "..\misc\peers.txt"; DestDir: "{app}"; AfterInstall: ConvertLineEndings
Source: "..\debian\changelog"; DestDir: "{app}"; DestName: "changelog.txt"; AfterInstall: ConvertLineEndings

[Icons]
Name: "{group}\Configuration"; Filename: "{app}\config.txt"
Name: "{group}\ReadMe"; Filename: "{app}\readme.txt"
Name: "{group}\Start KadNode"; Filename: "{app}\kadnode_start.bat"
Name: "{group}\Stop KadNode"; Filename: "{app}\kadnode_stop.bat"
Name: "{group}\{cm:UninstallProgram,KadNode}"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\readme.txt"; Flags: shellexec skipifdoesntexist postinstall skipifsilent
Filename: "{sys}\sc.exe"; Parameters: "create KadNode DisplayName= KadNode type= own start= auto error= normal binPath= ""\""{app}\kadnode.exe\"" --service-start --config \""{app}\config.txt\"" --peerfile \""{app}\peers.txt\"" --dns-port 53"""; Flags: runascurrentuser runhidden
Filename: "{sys}\sc.exe"; Parameters: "description KadNode ""KadNode is a decentralized DNS service. It intercepts and resolves DNS requests for a specific top level domain like \"".p2p\"". The mapping from a domain to an IP address is done by means of a Distributed Hash Table (DHT)."""; Flags: runascurrentuser runhidden
Filename: "{sys}\sc.exe"; Parameters: "start KadNode"; Description: {cm:LaunchMsg}; Flags: nowait postinstall skipifsilent runascurrentuser runhidden

[CustomMessages]
LaunchMsg=Start KadNode now

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop KadNode"; Flags: runhidden
Filename: "{sys}\timeout.exe"; Parameters: "/T 4"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete KadNode"; Flags: runhidden

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nKadNode is a decentralized DNS system based on a distributed hash table.%n%nBe aware that this package will change your DNS settings.

[Code]
const
  LF = #10;
  CR = #13;
  CRLF = CR + LF;

procedure ConvertLineEndings();
var
  FilePath : String;
  FileContents : String;
  UTF8FileContents : AnsiString;
begin
  FilePath := ExpandConstant(CurrentFileName);
  UTF8FileContents := String(FileContents);
  LoadStringFromFile(FilePath, UTF8FileContents);
  StringChangeEx(FileContents, LF, CRLF, False);
  SaveStringToFile(FilePath, UTF8FileContents, False);
end;
