# Notas de integracion

Cada carpeta de vendor documenta su API y sus endpoints.

- F5: iControl REST. Login en /mgmt/shared/authn/login, token en la cabecera X-F5-Auth-Token.
- Checkpoint: Management API. Se requiere el API key o usuario/clave con el scope adecuado.
- Palo Alto: XML API con api_key y las operaciones config/export.
- Fortinet: REST API con token bearer y cabecera X-CSRFTOKEN cuando aplica.

Todas usan los mismos nombres de variable para no cambiar los scripts al rotar claves.
