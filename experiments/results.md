# Resultados del experimento ofensivo vs. defensivo (T1046)

Generado por `experiments/run_experiment.py`. Perfiles simulados en tiempo + un perfil
LIVE real. Cada perfil pasa por: log tipo UFW -> parser -> detector.

## 1. Solo regla rápida (10 s, 15 destinos distintos)

| Perfil | Descripción | Eventos | Reglas | 1ª alerta tras | Veredicto |
|---|---|---|---|---|---|
| A. Rápido secuencial | 1-1024 a 1000 puertos/s | 1024 | fast | 0.0 s | **detectado** |
| B. Moderado (100/s) | 1-1024 a 100 puertos/s | 1024 | fast | 0.1 s | **detectado** |
| C. Lento aleatorio (1/s) | 1024 puertos barajados, 1 por segundo | 1024 | — | — | **EVADE (no detectado)** |
| D. Muy lento (1 / 30 s) | 1024 puertos, uno cada 30 s (~8,5 h) | 1024 | — | — | **EVADE (no detectado)** |
| E. Paranoico (1 / 5 min) | 100 puertos, uno cada 5 min (~8 h) | 100 | — | — | **EVADE (no detectado)** |
| F. Distribuido (128 IPs) | 1024 puertos repartidos, 8 puertos por IP | 1024 | — | — | **EVADE (no detectado)** |
| G. Dirigido (20 puertos) | 20 servicios comunes a 50/s | 20 | fast | 0.3 s | **detectado** |
| H. Dirigido lento (20 puertos) | 20 servicios comunes, 1 cada 10 s | 20 | — | — | **EVADE (no detectado)** |
| I. Barrido horizontal :22 | 1 puerto en 254 hosts a 50/s | 254 | fast | 0.3 s | **detectado** |
| Z1. Tráfico web normal | 40 clientes, 2000 conexiones a :443 | 2000 | — | — | **ok (sin alerta)** |
| Z2. Monitoreo legítimo | Nagios sondea 12 servicios cada 5 min | 144 | — | — | **ok (sin alerta)** |
| Z4. Monitoreo espaciado | 20 servicios, 1 sonda cada 15 s, ciclo de 5 min | 240 | — | — | **ok (sin alerta)** |
| Z5. Navegación web (eve.json) | 1 cliente, 40 servidores :443 en 6 s, flujos con tráfico real | 40 | — | — | **ok (sin alerta)** |
| Z3. Reintentos a un puerto | cliente reintenta :22 cada 2 s (fuerza bruta/mal config) | 300 | — | — | **ok (sin alerta)** |
| L. LIVE: portscan real | scanner real a 500/s, 600 puertos en localhost | 600 | fast | 0.0 s | **detectado** |

## 2. Reglas por origen (rápida 10 s/15 + lenta 1 h/40)

| Perfil | Descripción | Eventos | Reglas | 1ª alerta tras | Veredicto |
|---|---|---|---|---|---|
| A. Rápido secuencial | 1-1024 a 1000 puertos/s | 1024 | fast, slow | 0.0 s | **detectado** |
| B. Moderado (100/s) | 1-1024 a 100 puertos/s | 1024 | fast, slow | 0.1 s | **detectado** |
| C. Lento aleatorio (1/s) | 1024 puertos barajados, 1 por segundo | 1024 | slow | 38.8 s | **detectado** |
| D. Muy lento (1 / 30 s) | 1024 puertos, uno cada 30 s (~8,5 h) | 1024 | slow | 1149.8 s | **detectado** |
| E. Paranoico (1 / 5 min) | 100 puertos, uno cada 5 min (~8 h) | 100 | — | — | **EVADE (no detectado)** |
| F. Distribuido (128 IPs) | 1024 puertos repartidos, 8 puertos por IP | 1024 | — | — | **EVADE (no detectado)** |
| G. Dirigido (20 puertos) | 20 servicios comunes a 50/s | 20 | fast | 0.3 s | **detectado** |
| H. Dirigido lento (20 puertos) | 20 servicios comunes, 1 cada 10 s | 20 | — | — | **EVADE (no detectado)** |
| I. Barrido horizontal :22 | 1 puerto en 254 hosts a 50/s | 254 | fast, slow | 0.3 s | **detectado** |
| Z1. Tráfico web normal | 40 clientes, 2000 conexiones a :443 | 2000 | — | — | **ok (sin alerta)** |
| Z2. Monitoreo legítimo | Nagios sondea 12 servicios cada 5 min | 144 | — | — | **ok (sin alerta)** |
| Z4. Monitoreo espaciado | 20 servicios, 1 sonda cada 15 s, ciclo de 5 min | 240 | — | — | **ok (sin alerta)** |
| Z5. Navegación web (eve.json) | 1 cliente, 40 servidores :443 en 6 s, flujos con tráfico real | 40 | — | — | **ok (sin alerta)** |
| Z3. Reintentos a un puerto | cliente reintenta :22 cada 2 s (fuerza bruta/mal config) | 300 | — | — | **ok (sin alerta)** |
| L. LIVE: portscan real | scanner real a 500/s, 600 puertos en localhost | 600 | fast, slow | 0.0 s | **detectado** |

## 3. Reglas por defecto (anteriores + distribuida por destino: 20 puertos, 5 IPs, 60 s)

| Perfil | Descripción | Eventos | Reglas | 1ª alerta tras | Veredicto |
|---|---|---|---|---|---|
| A. Rápido secuencial | 1-1024 a 1000 puertos/s | 1024 | fast, slow | 0.0 s | **detectado** |
| B. Moderado (100/s) | 1-1024 a 100 puertos/s | 1024 | fast, slow | 0.1 s | **detectado** |
| C. Lento aleatorio (1/s) | 1024 puertos barajados, 1 por segundo | 1024 | slow | 38.8 s | **detectado** |
| D. Muy lento (1 / 30 s) | 1024 puertos, uno cada 30 s (~8,5 h) | 1024 | slow | 1149.8 s | **detectado** |
| E. Paranoico (1 / 5 min) | 100 puertos, uno cada 5 min (~8 h) | 100 | — | — | **EVADE (no detectado)** |
| F. Distribuido (128 IPs) | 1024 puertos repartidos, 8 puertos por IP | 1024 | distributed | 1.0 s | **detectado** |
| G. Dirigido (20 puertos) | 20 servicios comunes a 50/s | 20 | fast | 0.3 s | **detectado** |
| H. Dirigido lento (20 puertos) | 20 servicios comunes, 1 cada 10 s | 20 | — | — | **EVADE (no detectado)** |
| I. Barrido horizontal :22 | 1 puerto en 254 hosts a 50/s | 254 | fast, slow | 0.3 s | **detectado** |
| Z1. Tráfico web normal | 40 clientes, 2000 conexiones a :443 | 2000 | — | — | **ok (sin alerta)** |
| Z2. Monitoreo legítimo | Nagios sondea 12 servicios cada 5 min | 144 | — | — | **ok (sin alerta)** |
| Z4. Monitoreo espaciado | 20 servicios, 1 sonda cada 15 s, ciclo de 5 min | 240 | — | — | **ok (sin alerta)** |
| Z5. Navegación web (eve.json) | 1 cliente, 40 servidores :443 en 6 s, flujos con tráfico real | 40 | — | — | **ok (sin alerta)** |
| Z3. Reintentos a un puerto | cliente reintenta :22 cada 2 s (fuerza bruta/mal config) | 300 | — | — | **ok (sin alerta)** |
| L. LIVE: portscan real | scanner real a 500/s, 600 puertos en localhost | 600 | fast, slow | 0.0 s | **detectado** |

## 4. Ajustada (por defecto + 1 h/15 + 24 h/25)

| Perfil | Descripción | Eventos | Reglas | 1ª alerta tras | Veredicto |
|---|---|---|---|---|---|
| A. Rápido secuencial | 1-1024 a 1000 puertos/s | 1024 | daily, fast, slow, slow-15 | 0.0 s | **detectado** |
| B. Moderado (100/s) | 1-1024 a 100 puertos/s | 1024 | daily, fast, slow, slow-15 | 0.1 s | **detectado** |
| C. Lento aleatorio (1/s) | 1024 puertos barajados, 1 por segundo | 1024 | daily, slow, slow-15 | 13.2 s | **detectado** |
| D. Muy lento (1 / 30 s) | 1024 puertos, uno cada 30 s (~8,5 h) | 1024 | daily, slow, slow-15 | 389.0 s | **detectado** |
| E. Paranoico (1 / 5 min) | 100 puertos, uno cada 5 min (~8 h) | 100 | daily | 7512.4 s | **detectado** |
| F. Distribuido (128 IPs) | 1024 puertos repartidos, 8 puertos por IP | 1024 | distributed | 1.0 s | **detectado** |
| G. Dirigido (20 puertos) | 20 servicios comunes a 50/s | 20 | fast, slow-15 | 0.3 s | **detectado** |
| H. Dirigido lento (20 puertos) | 20 servicios comunes, 1 cada 10 s | 20 | slow-15 | 148.1 s | **detectado** |
| I. Barrido horizontal :22 | 1 puerto en 254 hosts a 50/s | 254 | daily, fast, slow, slow-15 | 0.3 s | **detectado** |
| Z1. Tráfico web normal | 40 clientes, 2000 conexiones a :443 | 2000 | — | — | **ok (sin alerta)** |
| Z2. Monitoreo legítimo | Nagios sondea 12 servicios cada 5 min | 144 | — | — | **ok (sin alerta)** |
| Z4. Monitoreo espaciado | 20 servicios, 1 sonda cada 15 s, ciclo de 5 min | 240 | slow-15 | 210.0 s | **FALSO POSITIVO** |
| Z5. Navegación web (eve.json) | 1 cliente, 40 servidores :443 en 6 s, flujos con tráfico real | 40 | — | — | **ok (sin alerta)** |
| Z3. Reintentos a un puerto | cliente reintenta :22 cada 2 s (fuerza bruta/mal config) | 300 | — | — | **ok (sin alerta)** |
| L. LIVE: portscan real | scanner real a 500/s, 600 puertos en localhost | 600 | daily, fast, slow, slow-15 | 0.0 s | **detectado** |

## 5. Z5 con el conteo ingenuo de flujos (`--eve-include-established`)

| Perfil | Descripción | Eventos | Reglas | 1ª alerta tras | Veredicto |
|---|---|---|---|---|---|
| Z5. Navegación web (eve.json) | 1 cliente, 40 servidores :443 en 6 s, flujos con tráfico real | 40 | fast, slow | 2.1 s | **FALSO POSITIVO** |

## Lectura

- La regla rápida atrapa lo ruidoso (A, B, G, I) en pocos segundos, pero **no ve** los
  escaneos que espaciaron sus paquetes más allá de la ventana (C, D, E, H) ni el F.
- Una ventana lenta cubre C y D, a cambio de riesgo de falsos positivos con monitoreo
  legítimo (Z2): por eso existe `--allow` y por eso importa el umbral por ventana.
- El escaneo **distribuido** (F) es el punto ciego de cualquier detector por IP de origen:
  cada IP toca pocos puertos (8). Solo aparece al correlacionar por **destino** (muchos
  puertos distintos recibidos por un host desde muchos orígenes): sección 3.
- Z5 (navegación web en `eve.json`) es un falso positivo clásico: un cliente que abre
  40 servidores :443 parece un barrido horizontal si se cuentan todos los flujos
  (sección 5). El parser descarta por defecto los flujos con tráfico real del servidor
  (`pkts_toclient > 2`) y solo cuenta los que mueren en el handshake, como un escaneo.
- Z4 es el costo de cubrir los escaneos lentos: un monitor legítimo que sondea 20
  servicios repartidos en el tiempo es indistinguible de un escaneo lento por patrón;
  se resuelve con `--allow` o con contexto (inventario de monitores), no con más umbral.
- Baja `threshold` y sube `window` reduce evasión y sube falsos positivos: es un
  compromiso medible, no una configuración "correcta".
