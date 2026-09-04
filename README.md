# bsc-suid-wazuh-evidence

Dieses Repository enthält ausgewählte Skripte, Konfigurationen und Beweisdaten der praktischen Versuche meiner Bachelorarbeit zum Thema Linux Hardening in Post-Exploitation-Szenarien.
Untersucht wird eine SUID-basierte Privilege Escalation auf einem Linux-System. Dabei werden präventive Maßnahmen mit der Erkennung und automatischen Korrektur durch Wazuh verglichen.

## Struktur

Die Beweisdaten sind nach den beiden beteiligten Systemen getrennt.

- evidence/noharded/  
  Beweisdaten des Linux-Zielsystems. Dazu gehören Active-Response-Skripte, SCA-Policies, Testnachweise und SHA-256-Prüfsummen.

- evidence/wazuh_manager/  
  Beweisdaten des Wazuh-Managers. Dazu gehören Wazuh-Regeln, Active-Response-Konfigurationen, Alerts, SCA-Ergebnisse und SHA-256-Prüfsummen.

Beide Ordner enthalten jeweils eine eigene README.md mit einer genaueren Beschreibung der enthaltenen Dateien.

## Integrität der Beweisdaten

Für zentrale Dateien und Beweisarchive wurden SHA-256-Prüfsummen gespeichert.

Die ursprünglichen Beweisdateien wurden für die Veröffentlichung nicht nachträglich vereinheitlicht oder formatiert. Unterschiedliche Log- und Dateiformate bleiben deshalb bewusst erhalten.

## Hinweis

Das Repository ergänzt die schriftliche Bachelorarbeit. Die vollständige Methodik, Auswertung und Einordnung der Ergebnisse befinden sich in der Arbeit selbst.
