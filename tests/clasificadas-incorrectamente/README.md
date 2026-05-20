# Extensiones clasificadas como BENIGNAS — posibles falsos negativos

Resultados de la corrida 2026-05-19T21-33-59 (100 extensiones, 10 batches).

Dataset: Malicious Browser Extensions (GitHub). El ground-truth asume que todas son maliciosas, por lo que las clasificadas como benigna son falsos negativos del sistema.

**Total: 13 / 98 completadas (13.27%)**

| # | Batch | Chrome Extension ID | Nombre | Versión | Risk score | Razones del veredicto |
|---|---|---|---|---|---|---|
| 1 | batch-01 | eggegjdejilddmnlglakcaigefefcdaf | InteractiveFics | 1.0.4 | 6 (LOW) | Modificación de páginas: La extensión puede modificar el aspecto o contenido de las páginas web que visitas. Evidencia: Detectamos que modifica el contenido de páginas web. / Seguimiento y privacidad: |
| 2 | batch-02 | eheagnmidghfknkcaehacggccfiidhik | Email checker - verify email address in 1-click | 2.6 | 0 (-) | No se detectaron capacidades críticas ni comportamiento sospechoso. |
| 3 | batch-04 | giaooddllfkkkblpaedgkhfmhocponbo | DeepSeek v3 | 1.11 | 4 (LOW) | Seguimiento y privacidad: La extensión usa APIs del navegador para observar activamente qué páginas visitas. / Acceso general al navegador: La extensión accede activamente a información de tus pestaña |
| 4 | batch-04 | glckmpfajbjppappjlnhhlofhdhlcgaj | Good Tab | 1.0.5 | 2 (LOW) | No se detectaron capacidades críticas ni comportamiento sospechoso. |
| 5 | batch-05 | goiffchdhlcehhgdpdbocefkohlhmlom | 股票提醒助手 | 3.8.0 | 5 (LOW) | No se detectaron capacidades críticas ni comportamiento sospechoso. |
| 6 | batch-05 | goikoilmhcgfidolicnbgggdpckdcoam | Amazon Character Count & Seller Tools | 3.0.1 | 2 (LOW) | Seguimiento y privacidad: La extensión usa APIs del navegador para observar activamente qué páginas visitas. / Acceso general al navegador: La extensión accede activamente a información de tus pestaña |
| 7 | batch-05 | hafhkoalnlpoifpidohfjlmeemfifndi | Grok AI | 3.1.0 | 0 (-) | Seguimiento y privacidad: La extensión se comunica con dominios externos que podrían estar relacionados con el rastreo de usuarios. Evidencia: Se comunica con estos sitios externos: chatgpt-5.easytool |
| 8 | batch-06 | hkhmodcdjhcidbcncgmnknjppphcpgmh | Amazon Sticky Notes | 3.0.1 | 10 (LOW) | Modificación de páginas: La extensión puede modificar el aspecto o contenido de las páginas web que visitas. Evidencia: Detectamos que modifica el contenido de páginas web. / Acceso general al navegad |
| 9 | batch-06 | hodafefeincjlgijbiabbmaffambjeaa | Grok Sidebar | 1.0 | 2 (LOW) | No se detectaron capacidades críticas ni comportamiento sospechoso. |
| 10 | batch-06 | hpkfkbmcphnigepfjmapkdaedglohgjg | Flappy Birdie (Night farm mode) | 1.5.3 | 0 (-) | Lectura de información en páginas: La extensión declara acceso amplio a sitios web, pero no vimos que lo use para leer datos de los usuarios. Evidencia: Tiene permiso para acceder a todos los sitios w |
| 11 | batch-06 | iclckldkfemlnecocpphinnplnmijkol | SQLite browser | 1.4 | 0 (-) | No se detectaron capacidades críticas ni comportamiento sospechoso. |
| 12 | batch-07 | ihdnbohcfnegemgomjcpckmpnkdgopon | AI Sentence Rewriter | 2.1 | 0 (-) | No se detectaron capacidades críticas ni comportamiento sospechoso. |
| 13 | batch-08 | johobikccpnmifjjpephegmfpipfbfme | Amazon Stock Checker & 999 Trick | 3.0.1 | 20 (LOW) | Modificación de páginas: La extensión puede modificar el aspecto o contenido de las páginas web que visitas. Evidencia: Detectamos que modifica el contenido de páginas web. / Acceso general al navegad |

## Solo los Chrome Extension IDs

```
eggegjdejilddmnlglakcaigefefcdaf
eheagnmidghfknkcaehacggccfiidhik
giaooddllfkkkblpaedgkhfmhocponbo
glckmpfajbjppappjlnhhlofhdhlcgaj
goiffchdhlcehhgdpdbocefkohlhmlom
goikoilmhcgfidolicnbgggdpckdcoam
hafhkoalnlpoifpidohfjlmeemfifndi
hkhmodcdjhcidbcncgmnknjppphcpgmh
hodafefeincjlgijbiabbmaffambjeaa
hpkfkbmcphnigepfjmapkdaedglohgjg
iclckldkfemlnecocpphinnplnmijkol
ihdnbohcfnegemgomjcpckmpnkdgopon
johobikccpnmifjjpephegmfpipfbfme
```

## Archivos .crx originales (para volver a analizarlos)

```
eggegjdejilddmnlglakcaigefefcdaf.crx
eheagnmidghfknkcaehacggccfiidhik.crx
giaooddllfkkkblpaedgkhfmhocponbo.crx
glckmpfajbjppappjlnhhlofhdhlcgaj.crx
goiffchdhlcehhgdpdbocefkohlhmlom.crx
goikoilmhcgfidolicnbgggdpckdcoam.crx
hafhkoalnlpoifpidohfjlmeemfifndi.crx
hkhmodcdjhcidbcncgmnknjppphcpgmh.crx
hodafefeincjlgijbiabbmaffambjeaa.crx
hpkfkbmcphnigepfjmapkdaedglohgjg.crx
iclckldkfemlnecocpphinnplnmijkol.crx
ihdnbohcfnegemgomjcpckmpnkdgopon.crx
johobikccpnmifjjpephegmfpipfbfme.crx
```
