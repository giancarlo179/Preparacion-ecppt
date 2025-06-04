## Ver servicios 

Get-Service | ForEach-Object {$_.Name}


## Listar ubicaciones de los servicios ejecutados 

Get-WmiObject -class win32_service |Format-List *

Get-WmiObject -class win32_service |Sort-Object -Unique PathName | fl Pathname

## Listar procesos sin que se repitan 

Get-Process | Sort-Object -Unique

