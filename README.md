🕵️‍♂️ BountyHunter - Suite de Automatización para Pentesting & Bug Bounty

BountyHunter es una herramienta todo-en-uno en Bash diseñada para automatizar las fases principales de un pentest o cacería de bugs.
Integra las mejores herramientas de reconocimiento, escaneo y explotación en un solo flujo, generando un reporte automático con resultados listos para análisis o presentación.


🔑 Características principales

🚀 Reconocimiento de subdominios → subfinder, assetfinder, chaos

🌐 Hosts vivos y tecnologías → dnsx, httpx

📜 Recolección de URLs → gau, waybackurls, katana

🔎 Fuzzing de directorios → ffuf

🔥 Escaneo de puertos → naabu

🛡️ Escaneo avanzado de servicios → nmap con scripts específicos

💣 Fuerza bruta de credenciales → hydra

🎯 Fingerprinting con Metasploit → módulos auxiliares para cada servicio

🧬 Detección de vulnerabilidades → nuclei

⚡ Testing XSS → dalfox

📑 Reporte automático en Markdown con:

Executive Summary (tabla) de servicios, credenciales y versiones detectadas

Resultados completos de cada herramienta

📂 Salida de la herramienta

Carpeta por target (results-dominio-fecha) con todos los logs y resultados.

Reporte final en Markdown (Reporte_target.md) con:

Subdominios encontrados

Hosts vivos y tecnologías

Puertos abiertos

Vulnerabilidades (Nuclei, Dalfox)

Credenciales Hydra

Resultados de Nmap y Metasploit

🤖 Objetivo

Esta herramienta busca ahorrar tiempo en procesos repetitivos del pentest, unificando múltiples técnicas en un solo script.
Es ideal para:

🔍 Bug bounty hunters

🛡️ Red Teams

🧑‍💻 Pentesters que quieran un flujo rápido y automatizado

⚠️ Aviso ético y legal:
BountyHunter debe usarse únicamente en sistemas que tengas autorización para auditar (programas de bug bounty, entornos de laboratorio o clientes que lo permitan).
El uso indebido puede acarrear consecuencias legales.

👉 En resumen:
BountyHunter = Reconocimiento + Escaneo + Explotación + Reporte → en un solo click.
