# Bedienungsanleitung: TCP-RCA-Analysewerkzeug

## Zweck

Dieses Werkzeug analysiert PCAP- oder PCAPNG-Mitschnitte von TAPs direkt am lokalen Server und erstellt eine passive TCP-Root-Cause-Analyse. Es berücksichtigt lokale Servernetze, vollständige Handshakes, RTT, Retransmissions, Loss-Indikatoren, Receiver-Window-Verlauf, Throughput, Wire-Rate-Bezug zu 25 Gbit/s sowie eine erste regelbasierte RCA-Klassifikation.[cite:27][cite:9]

Die Auswertung erzeugt CSV-, JSON- und HTML-Artefakte. Sessions mit vollständigem 3-Way-Handshake werden als `full_rca` bearbeitet; unvollständige Sessions werden reduziert ausgewertet, da Window Scaling und initiale RTT sonst nicht belastbar vorliegen.[cite:25][cite:9]

## Voraussetzungen

Benötigt werden:
- Python 3.9 oder neuer
- `tshark` im Pfad
- Ein PCAP- oder PCAPNG-Mitschnitt mit TCP-Traffic

Das Skript nutzt TShark zur Extraktion standardisierter TCP-Felder und Wireshark-Analysefelder wie `tcp.analysis.ack_rtt`, `tcp.analysis.bytes_in_flight`, `tcp.analysis.retransmission`, `tcp.analysis.duplicate_ack`, `tcp.analysis.window_full` und `tcp.analysis.zero_window`.[cite:27]

## Dateien

Das Paket besteht aus:
- `tcp_rca.py` – Python-Skript zur Analyse
- `bedienungsanleitung_tcp_rca.md` – diese Anleitung

Die Analyse erzeugt im Zielverzeichnis typischerweise:
- `flows_summary.csv`
- `flows_intervals_100ms.csv`
- `flows_intervals_1s.csv`
- `flows_events.csv`
- `flows_summary.json`
- `flows_intervals_100ms.json`
- `flows_intervals_1s.json`
- `flows_events.json`
- `run_metadata.json`
- `report.html`

## Schnellstart

### 1. Template-Konfiguration erzeugen

```bash
python3 tcp_rca.py --export-config config.json
```

Dadurch wird eine JSON-Konfigurationsdatei mit Standardwerten geschrieben. Standardmäßig ist das lokale Netz auf `10.1.1.0/24` gesetzt und die Line-Rate auf 25 Gbit/s.[cite:9]

### 2. Konfiguration anpassen

Beispiel:

```json
{
  "local_networks": ["10.1.1.0/24", "10.2.0.0/16"],
  "line_rate_bps": 25000000000,
  "window_sizes_ms": [100, 1000],
  "baseline_thresholds": {
    "rwnd_headroom_mss_multiplier": 3.0,
    "dispersion_low": 0.20,
    "retransmission_high": 0.02,
    "receiver_limitation_high": 0.30,
    "burstiness_high": 0.50,
    "alp_idle_seconds": 5.0
  }
}
```

Die enthaltenen Thresholds sind bewusst Baseline-Startwerte. Die Literatur empfiehlt keine universellen festen Schwellwerte, sondern eine spätere datengetriebene Anpassung an reale Traces.[cite:47][cite:9]

### 3. Analyse starten

```bash
python3 tcp_rca.py capture.pcapng --config config.json --outdir output/run1
```

Das Skript ruft dann TShark selbst auf, extrahiert TCP-Felder und erstellt die Ausgabedateien im Zielverzeichnis. Die Analyse betrachtet nur TCP-Flows mit genau einer lokalen und einer nicht-lokalen Seite bezogen auf die konfigurierten lokalen Netze.

## Alternative: Bereits extrahierte CSV nutzen

Wenn TShark separat ausgeführt wurde, kann statt der PCAP eine vorhandene CSV-Datei verarbeitet werden:

```bash
python3 tcp_rca.py --csv-input tshark_extract.csv --config config.json --outdir output/run1
```

Das ist nützlich für Debugging oder wiederholte Tests gegen denselben TShark-Export.

## Was das Skript auswertet

### Handshake und Rollen

Das Skript erkennt lokale und entfernte Partner anhand der konfigurierten Netze. Wenn der erste beobachtete SYN vom lokalen Host kommt und SYN, SYN/ACK und finales ACK vorhanden sind, wird der Flow als vollständiger Handshake markiert und `rtt_handshake_ms` aus SYN zu SYN/ACK gebildet.[cite:9][cite:25]

Zusätzlich werden im Handshake festgehalten:
- MSS lokal und remote
- Window Scale lokal und remote
- SACK Permitted
- Presence von TCP Timestamps

### RTT

Das Werkzeug dokumentiert RTT auf drei Wegen:
- `rtt_handshake_ms` aus dem 3-Way-Handshake.[cite:9]
- `ack_rtt_*` aus `tcp.analysis.ack_rtt`, sofern Wireshark/TShark die Werte liefert.[cite:27]
- `ts_rtt_*` aus TCP Timestamp Option über `TSval/TSecr`, sofern vorhanden.[cite:9]

### Sendefortschritt und Receiver Window

Das RX-Window der Gegenseite wird als limitierendes TX-Window des lokalen Senders verfolgt. Dazu wird `tcp.window_size_value` mit dem im Handshake beobachteten Window-Scale-Faktor skaliert; daraus entstehen `peer_rwnd_bytes`, `bytes_in_flight` und `peer_rwnd_headroom`.[cite:25][cite:27]

Zusätzlich dokumentiert das Skript Wireshark-Ereignisse wie `window_full`, `zero_window` und `window_update`, die Receiver-Limitierung oder Recovery sichtbar machen.[cite:27]

### Loss und Recovery

Das Skript schreibt folgende Ereignisse weg:
- Retransmission
- Fast Retransmission
- Spurious Retransmission
- Duplicate ACK
- Out-of-order
- Lost Segment
- Partial ACK
- Window Full
- Zero Window
- Window Update

Diese Trennung ist wichtig, weil Duplicate ACK und Out-of-order nicht automatisch echten Pfadverlust bedeuten. Wireshark behandelt diese Zustände separat.[cite:27]

### Zeitfenster

Es werden standardmäßig zwei Aggregationsraster erzeugt:
- `100 ms`
- `1 s`

Damit lassen sich sowohl Bursts als auch lesbare Session-Verläufe dokumentieren. Für jede Periode werden u. a. Throughput, Wire-Rate-Anteil, ACK-Fortschritt, RTT-Stichproben, Bytes-in-Flight, Receiver-Window-Werte und Event-Zähler gespeichert.[cite:9]

## Ergebnisdateien lesen

### flows_summary.csv / flows_summary.json

Enthält eine Zeile pro Flow mit den wichtigsten Kennzahlen:
- Session-Identität
- Handshake-Status
- RTT-Werte
- MSS und Window Scale
- Gesamt-Throughput
- geschätzter mittlerer 25G-Wire-Anteil
- Retransmission- und Receiver-Limitation-Scores
- RCA-Klasse, Confidence und Reasons

### flows_intervals_100ms.csv und flows_intervals_1s.csv

Enthält Intervallmetriken pro Flow. Das ist die Basis für spätere Visualisierung, Tuning und RCA-Validierung.

### flows_events.csv

Enthält einzelne Ereignisse mit Zeitstempel, Richtung und Paketbezug. Diese Datei ist besonders nützlich für die manuelle Gegenprüfung in Wireshark.

### report.html

Der HTML-Report ist eine lesbare Arbeitsansicht mit:
- Run-Zusammenfassung
- Verteilung der RCA-Klassen
- Tabelle auffälliger Flows
- Kurzdetails für Top-Flows

Dieser Report ist bewusst einfach gehalten und dient als Baseline-Artefakt. Er ersetzt keine tiefe Visualisierung, ist aber für eine erste Sichtung geeignet.

## RCA-Klassifikation

Die aktuelle Implementierung nutzt eine erste regelbasierte Baseline. Sie orientiert sich am Literaturmuster:
- niedriger Dispersion-Score → `unshared_bottleneck`
- hoher Retransmission-Score → `shared_bottleneck`
- hoher Receiver-Limitation-Score → `receiver_limitation`
- hohe Burstiness bei sonst unauffälliger Lage → `transport_limitation`
- sonst `mixed_or_unknown`.[cite:9]

Wichtig: Diese Einstufung ist eine **Startstufe**, kein fertiges Orakel. Die Literatur empfiehlt klar, Thresholds aus echten Daten zu kalibrieren und später datengetrieben zu optimieren.[cite:47][cite:9]

## Praktische Grenzen

Das Werkzeug ist absichtlich nützlich, aber noch nicht allwissend.

Bekannte Grenzen:
- Kapazitätsschätzung ist noch nur grob über Line-Rate angenähert; der passive Dispersion-Ansatz für hohe Kapazitäten ist in der Literatur selbst als schwierig beschrieben.[cite:9]
- Flows ohne vollständigen Handshake werden nur reduziert analysiert.[cite:25]
- TSO/GSO/GRO/LRO-Artefakte oder Capture-Eigenheiten können die Interpretation von MSS, Segmentierung und Burst-Verhalten verfälschen.[cite:27]
- Die ALP-/Bulk-Erkennung ist in diesem Skript noch nicht voll ausgebaut, sondern nur als Platzhalter im Konfigschema vorgesehen.[cite:9]
- Stufe 2, also datengetriebenes Tuning und optionales ML, ist noch nicht implementiert; das Skript bildet primär Stufe 1 ab.[cite:47]

Das ist wichtig: Das Skript ist ein belastbares Startgerüst, aber noch kein finales Produktivsystem.

## Typischer Arbeitsablauf

1. PCAP mit servernahem TAP bereitstellen.
2. Template-Konfiguration erzeugen.
3. Lokale Netze und Threshold-Baseline anpassen.
4. Analyse laufen lassen.
5. `flows_summary.csv` und `report.html` sichten.
6. Auffällige Flows anhand `flows_events.csv` in Wireshark validieren.
7. Später gelabelte Flows sammeln und Thresholds datengetrieben tunen.[cite:47][cite:9]

## Kill-Switch

Die erzeugte RCA-Klasse sollte nicht blind vertraut werden, wenn einer dieser Punkte auftritt:
- Handshake fehlt
- Window Scale des Peers fehlt
- ACK-Richtung ist lückenhaft
- Bytes-in-Flight sind offensichtlich inkonsistent
- Timestamps im Capture sind unbrauchbar

In diesen Fällen sind Rohmetriken und Event-Dokumentation meist noch nützlich, aber die RCA-Klassifikation ist nur eingeschränkt belastbar.[cite:25][cite:27][cite:9]

## Nächste Ausbaustufe

Für die nächste Stufe sind diese Erweiterungen sinnvoll:
- saubere ALP-/Bulk-Transfer-Erkennung
- passive Capacity Estimation nach Literatur
- konfigurierbare Threshold-Profile `baseline` und `tuned`
- Label-Import für gelabelte Flows
- datengetriebenes Tuning via Grid Search oder Decision Tree
- verbesserter HTML-Report mit echten Diagrammen.[cite:47][cite:9]
