# 🛡️ SENTINEL AI

**Intelligent Cyber Attack Detection System for Windows**

Développé par **404sec**

---

### Description

SENTINEL AI est un système de surveillance défensive conçu pour Windows.  
Il analyse en temps réel les journaux Windows Event Logs + Sysmon, détecte les comportements suspects et affiche les alertes dans un tableau de bord moderne.

### Fonctionnalités

- Analyse des journaux Windows (Security + Sysmon)
- Détection de connexions inhabituelles
- Identification de comportements potentiellement malveillants (processus, PowerShell obfuscqué, etc.)
- Détection de modifications suspectes de fichiers
- Alertes en temps réel avec scoring de gravité
- Tableau de bord web clair et réactif
- Surveillance de fichiers en temps réel (watchdog)

### Technologies

- Python 3.10+
- FastAPI
- Sysmon
- Windows Event Logs
- Watchdog + psutil

### Prérequis

1. Windows 10 / 11
2. **Sysmon** installé et configuré
3. Python 3.10 ou supérieur
4. Exécution en **Administrateur** (obligatoire pour lire les Event Logs)

### Installation

```bash
git clone https://github.com/404sec/sentinel-ai.git
cd sentinel-ai
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Lancement

```bash
# Lancer en tant qu'Administrateur
python main.py
```

Puis ouvre ton navigateur :  
**http://127.0.0.1:8888**

### Auteur

**404sec**  
Projet open-source à but défensif et éducatif.

### Disclaimer

Cet outil est uniquement destiné à un usage défensif et légitime sur des machines que vous possédez ou administrez.  
Toute utilisation malveillante est strictement interdite.
