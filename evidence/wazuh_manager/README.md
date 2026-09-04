# Evidence – wazuh_manager

Dieser Ordner enthält die für die Bachelorarbeit verwendeten Beweisdaten des Wazuh-Managers.
Die Dateien dokumentieren Wazuh-Regeln, Active-Response-Konfigurationen, Alerts, SCA-Ergebnisse und zugehörige SHA-256-Prüfsummen.
Die ursprünglichen Beweisdaten wurden nicht nachträglich vereinheitlicht oder formatiert. Unterschiedliche Dateiformate bleiben deshalb bewusst erhalten.

## Ordnerstruktur

### 01_archives

Enthält frühere vollständige Beweisarchive des Wazuh-Managers.

- BA_FINAL_EVIDENCE_wazuh_20260815.tar.gz
- BA_FINAL_EVIDENCE_wazuh_20260815.tar.gz.sha256
- BA_FINAL_EVIDENCE_wazuh_20260816_ZeroTouch.tar.gz
- BA_FINAL_EVIDENCE_wazuh_20260816_ZeroTouch.tar.gz.sha256

Die zugehörigen SHA-256-Dateien dienen zur Integritätskontrolle der Archive.

### 02_rules

Enthält die für die Versuche verwendeten lokalen Wazuh-Regeln.

- local_rules_final.xml
- local_rules_generalisiert_100205.xml

local_rules_final.xml enthält unter anderem die Regeln 100202, 100203, 100204 und die zunächst auf sys-maintenance beschränkte Regel 100205.
local_rules_generalisiert_100205.xml enthält die später angepasste Fassung von Regel 100205. In dieser Version wird nicht mehr nur ein fester Dateiname geprüft. Stattdessen gilt die Regel für passende Dateien unter /usr/local/bin.

### 03_active_response

Enthält die verwendeten Active-Response-Skripte und die zugehörigen Konfigurationsblöcke.

- bsc-suid-generic-hardening.py
- bsc-suid-generic-hardening_v5_final.py
- ossec_active_response_block_20260901.txt
- ossec_ar_100205_block.txt

Die Dateien dokumentieren die automatische Entfernung des SUID-Bits sowie die Verknüpfung der Active Response mit den verwendeten Wazuh-Regeln.

### 04_test_evidence

Enthält Beweisdaten zu einzelnen Testfällen.

#### ar2

- 3_manager-alerts.txt
- 4_manager-alerts-json.txt

Die Dateien dokumentieren den Wazuh-Alert für Regel 100204 auf dem Manager.

#### p2

- p2_passed_alert.json
- p2_passed_summary.json

Die Dateien dokumentieren den bestandenen SCA-Test für den vorgesehenen nosuid-Mount-Zustand.

#### versuch5

- alert_100205_final.json

Dokumentiert den FIM-basierten Alert für sys-maintenance, nachdem das SUID-Bit erneut gesetzt wurde.

#### generalisierung

- alert_100205_generic_final.json

Dokumentiert den späteren Test der generalisierten Regel 100205 mit bsc-generic-check.

### 05_config

Enthält zusätzlich gesicherte Wazuh-Konfiguration.

- agent.conf_20260901.xml

### 06_hashes

Enthält SHA-256-Prüfsummen für ausgewählte Dateien.

- SHA256SUMS_20260901.txt
- wazuh_logs.sha256

SHA256SUMS_20260901.txt enthält Prüfsummen für mehrere Konfigurations- und Beweisdateien.
wazuh_logs.sha256 enthält die Prüfsummen der AR2-Manager-Logs.

## Hinweis zu den Beweisdaten

Die einzelnen Dateien haben teilweise unterschiedliche Strukturen. Das ist beabsichtigt.
Je nach Test wurden unterschiedliche Nachweise benötigt. Dazu gehören Wazuh-Alerts, Regelkonfigurationen, Active-Response-Blöcke, SCA-Ergebnisse und JSON-Rohdaten.
Die Dateien wurden deshalb nicht nachträglich auf ein gemeinsames Format gebracht.