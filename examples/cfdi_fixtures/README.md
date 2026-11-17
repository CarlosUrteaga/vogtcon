<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Datos del ejemplo CFDI

Los XML, el perfil y los CSV son datos sintéticos originales. No son comprobantes
timbrados válidos: omiten campos que no consume esta demostración. `F.xml` está
malformado deliberadamente. `scenarios.json` declara el resultado esperado por caso.
El código y los fixtures originales se distribuyen bajo Apache-2.0.

`catalog.json` contiene datos de referencia del SAT, no reglas fiscales inventadas
para la prueba. Se extrajeron 24 claves de `c_UsoCFDI` y 19 de `c_RegimenFiscal`
del [archivo oficial de 2026-11-06](http://omawww.sat.gob.mx/tramitesyservicios/Paginas/documentos/catCFDI_V_4_20261106.xls),
descargado el 2026-11-15. `catalog_manifest.json` registra URL, hashes SHA-256 del
archivo original y de la extracción, hojas y transformación. Los datos del SAT
conservan su procedencia; el copyright del proyecto no atribuye su autoría al proyecto.
La descarga original fue por HTTP porque el servidor HTTPS no respondió: el hash
fija los bytes obtenidos, no es una firma de autenticidad del SAT.

La extracción guarda claves, tipo de persona, regímenes compatibles y vigencias
por fila; omite las descripciones. Para reproducirla con `xlrd==2.0.2`, leer las
filas desde la séptima de ambas hojas, columnas A/C/D/E/F y además G en `c_UsoCFDI`.
Convertir códigos numéricos a strings sin decimales y fechas Excel a ISO usando el
`datemode` del libro. Las claves JSON son `person_types`, `regimes` (solo usos),
`valid_from`, `valid_until`; `Sí` se transforma a `fisica` o `moral` según la columna.
Una celda vacía de fin de vigencia se transforma a `null`. Serializar con
`json.dumps(data, ensure_ascii=False, indent=2) + "\n"`, respetando el orden de filas.
El ejemplo verifica el hash de la extracción antes de iniciar el agente.

Política del ejemplo: egresos negativos, importe MXN exacto con `Decimal`, fecha
bancaria entre la fecha local de emisión y siete días calendario después, inclusive.
No convierte zonas horarias ni usa la descripción bancaria para decidir coincidencias.
Los UUID y transaction IDs son identificadores de evidencia; RFC, nombres, XML y
descripciones no se entregan al modelo ni a la consola. Aun con estas precauciones,
los UUID reales podrían ser sensibles: la consola incluida está destinada a fixtures.

Un resultado `matched` indica un candidato según esta política limitada, no validez
fiscal, deducibilidad ni confirmación bancaria del pago. El parser no valida XSD,
sellos, certificados, timbres ni estado de cancelación. Un código ausente en la
instantánea produce `needs_review`, no una afirmación de invalidez fiscal.
