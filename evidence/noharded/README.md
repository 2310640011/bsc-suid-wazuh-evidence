# Evidence – noharded

Dieser Ordner enthält die für die Bachelorarbeit verwendeten Beweisdaten des Linux-Zielsystems noharded.
Die Dateien dokumentieren ausgewählte Testfälle, Active-Response-Skripte, SCA-Policies und zugehörige SHA-256-Prüfsummen. Die Beweisdaten wurden nach der Sicherung nicht inhaltlich vereinheitlicht oder nachträglich formatiert. Unterschiedliche Logformate bleiben deshalb bewusst erhalten.

## Ordnerstruktur

### 01_archives

Enthält frühere vollständige Beweisarchive des Zielsystems.

- BA_FINAL_EVIDENCE_noharded_20260814.tar.gz
- BA_FINAL_EVIDENCE_noharded_20260814.tar.gz.sha256
- BA_FINAL_EVIDENCE_noharded_20260816_ZeroTouch.tar.gz
- BA_FINAL_EVIDENCE_noharded_20260816_ZeroTouch.tar.gz.sha256

Die zugehörigen SHA-256-Dateien dienen zur Integritätskontrolle der Archive.

### 02_active_response

Enthält die auf dem Zielsystem verwendeten Active-Response-Skripte.

- bsc-suid-hardening.py
- bsc-suid-generic-hardening.py

bsc-suid-hardening.py ist auf das Testartefakt sys-maintenance und die Wazuh-Regel 100202 ausgerichtet.
bsc-suid-generic-hardening.py verarbeitet die später verwendeten Regeln 100204 und 100205 und kann erkannte SUID-Dateien unter /usr/local/bin behandeln.

### 03_sca

Enthält die für die Zustandskontrolle verwendeten SCA-Policies.

- bsc_suid_hardening.yml
- bsc_prevention_hardening.yml

bsc_suid_hardening.yml prüft den SUID-Zustand von /usr/local/bin/sys-maintenance.
bsc_prevention_hardening.yml prüft, ob /opt/bsc-tools mit der Mount-Option nosuid eingebunden ist.

### 04_test_evidence

Enthält zusätzliche Beweisdaten zu einzelnen Versuchen.

#### ar2

- 1_active-response-success.txt
- 2_auditd-raw-event.txt

Die Dateien dokumentieren das Audit-Ereignis und die zugehörige Active Response für AR2.

#### p1

- p1_evidence.txt

Dokumentiert den Präventionstest mit der Mount-Option nosuid.

#### versuch5

- v5_evidence.txt

Dokumentiert den FIM-basierten Trigger und die anschließende Active Response vor dem späteren Ausnutzungsversuch.

#### generalisierung

- generalisierung_evidence.txt

Dokumentiert den späteren Test der generalisierten Regel 100205 mit einer neuen Datei unter /usr/local/bin.

## SHA-256-Prüfsummen

Der Ordner 05_hashes enthält die Prüfsummen für die zusätzlich gesicherten Dateien.

### SHA256SUMS_noharded_20260901.txt

Enthält Prüfsummen für:

- bsc_prevention_hardening.yml
- bsc-suid-hardening.py
- bsc_suid_hardening.yml

### SHA256SUMS_noharded_20260904.txt

Enthält die Prüfsumme für:

- bsc-suid-generic-hardening.py

### Weitere Prüfsummen

- noharded_logs.sha256 gehört zu den AR2-Beweisdaten.
- p1_evidence.txt.sha256 gehört zu p1_evidence.txt.
- v5_evidence.txt.sha256 gehört zu v5_evidence.txt.
- generalisierung_evidence.txt.sha256 gehört zu generalisierung_evidence.txt.

Die SHA-256-Prüfsummen dienen dazu, die Integrität der gesicherten Dateien zu überprüfen.

## Hinweis zu den Beweisdaten

Die einzelnen Beweisdateien haben teilweise unterschiedliche Strukturen. Das ist beabsichtigt. Je nach Test wurden unterschiedliche technische Nachweise benötigt, zum Beispiel Audit-Ereignisse, Active-Response-Logs, Dateiberechtigungen, Mount-Zustände oder praktische Retests.
Die Originalinhalte wurden deshalb nicht nachträglich auf ein gemeinsames Format gebracht.