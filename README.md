# DC03 - HackMyVM (Medium)

![DC03.png](DC03.png)

## Übersicht

*   **VM:** DC03
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=DC03)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 13. August 2024
*   **Original-Writeup:** https://alientec1908.github.io/DC03_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser "Medium"-Challenge war es, Root- (Domain Admin-) Zugriff auf der Maschine "DC03", einem Active Directory Domain Controller, zu erlangen. Nach initialer AD-Enumeration wurden Benutzer mittels `ldapnomnom` identifiziert. Da direkte Passwortangriffe scheiterten, wurde ein LLMNR-Poisoning-Angriff mit `Responder.py` durchgeführt, wodurch der NTLMv2-Hash des Benutzers `xkate578` erbeutet und mit `john` geknackt wurde. Mit diesen Credentials wurde Zugriff auf einen SMB-Share und die User-Flag erlangt. BloodHound und `pywerview` deckten auf, dass `xkate578` Mitglied der `Account Operators` ist und der Benutzer `fbeth103` (Mitglied der `Operators`, die wiederum Mitglied der `Domain Admins` sind) existiert. Das Passwort von `fbeth103` wurde mittels `bloodyAD` (als `xkate578`) geändert. Mit den neuen Credentials für `fbeth103` wurde via `crackmapexec --ntds` die NTDS.dit gedumpt. Der daraus extrahierte NTLM-Hash des Domain-Administrators ermöglichte schließlich via `evil-winrm` (Pass-the-Hash) den Zugriff und das Auslesen der Root-Flag.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `enum4linux`
*   `nmap`
*   `nxc` (netexec, auch als `crackmapexec` referenziert)
*   `ldapnomnom`
*   `smbclient`
*   `snmpwalk`
*   `Responder.py`
*   `john` (John the Ripper)
*   `neo4j` (Datenbank für BloodHound)
*   `bloodhound-python`
*   `pywerview` (AD Enumeration)
*   `impacket-changepasswd` (Impacket)
*   `rpcclient` (Impacket)
*   `bloodyAD`
*   `evil-winrm`
*   Standard Linux-Befehle (`vi`, `grep`, `ls`, `cd`, `cat`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "DC03" gliederte sich in folgende Phasen:

1.  **Reconnaissance & AD Enumeration:**
    *   IP-Findung mittels `arp-scan` (Ziel: `192.168.2.116`, Hostname `dc03.hmv`).
    *   `enum4linux` identifizierte die Domain `SUPEDECDE` und den Hostnamen `DC01` (NetBIOS-Name). Null-Session-Zugriff wurde blockiert.
    *   `nmap`-Scan bestätigte einen Windows Domain Controller (Domain `SUPEDECDE.LOCAL`) mit typischen AD-Diensten. SMB-Signing war aktiv.

2.  **User Enumeration & LLMNR Poisoning:**
    *   Anonyme SMB-Share-Enumeration scheiterte.
    *   `ldapnomnom` wurde zur Benutzerenumeration über LDAP verwendet und fand u.a. den Benutzer `xkate578`.
    *   Passwort-Spraying und Brute-Force-Angriffe gegen SMB mit den gefundenen Benutzern waren erfolglos.
    *   `Responder.py` wurde für LLMNR/NBT-NS-Poisoning eingesetzt. Ein NTLMv2-Hash für den Benutzer `soupedecode\xkate578` wurde abgefangen.
    *   Der Hash wurde mit `john` und `rockyou.txt` zum Passwort `jesuschrist` geknackt.

3.  **SMB Access & User Flag:**
    *   Mit den Credentials `XKATE578:jesuschrist` wurde via `nxc` Zugriff auf SMB-Shares erlangt, darunter ein beschreibbarer Share namens `share`.
    *   Über `smbclient` wurde auf den `share`-Ordner zugegriffen und die `user.txt` heruntergeladen und gelesen.

4.  **Active Directory Enumeration (BloodHound & pywerview):**
    *   `bloodhound-python` wurde mit den Credentials von `xkate578` ausgeführt, um AD-Informationen zu sammeln.
    *   Die Analyse (teilweise mit `pywerview` verifiziert) ergab:
        *   `xkate578` ist Mitglied der Gruppe `Account Operators`.
        *   Die Gruppe `Operators` ist Mitglied der `Domain Admins`.
        *   Der Benutzer `fbeth103` ist Mitglied der Gruppe `Operators`.

5.  **Privilege Escalation (Forced Password Change):**
    *   Es wurde versucht, das Passwort des Benutzers `fbeth103` (indirekter Domain Admin) mit den Rechten von `xkate578` (Account Operator) zu ändern.
    *   Nach fehlgeschlagenen Versuchen mit `impacket-changepasswd` und `rpcclient` war `bloodyAD` erfolgreich und setzte das Passwort von `fbeth103` auf `Password123` (später im Log auf `Pass123!`).

6.  **NTDS Dump & Pass-the-Hash (Root Flag):**
    *   Mit den neuen Credentials `fbeth103:Pass123!` wurde via `crackmapexec --ntds` die NTDS.dit-Datenbank vom DC gedumpt.
    *   Daraus wurde der NTLM-Hash des Domain-Administrators `Administrator` (`2176416a80e4f62804f101d3a55d6c93`) extrahiert.
    *   Mittels `evil-winrm` und Pass-the-Hash (`-H '2176...' -u 'Administrator'`) wurde eine administrative PowerShell-Sitzung auf dem DC erlangt.
    *   In dieser Sitzung wurde die `root.txt` auf dem Desktop des Administrators gefunden und ausgelesen.

## Wichtige Schwachstellen und Konzepte

*   **LLMNR/NBT-NS Poisoning:** Ermöglichte das Abfangen eines NTLMv2-Hashes, der anschließend geknackt wurde.
*   **Schwache Passwörter:** Das Passwort `jesuschrist` für `xkate578` war leicht zu knacken.
*   **Unsichere Share-Berechtigungen:** Der `share`-Ordner enthielt die User-Flag und war für `xkate578` zugänglich.
*   **Überprivilegierte Gruppe (`Account Operators`):** Die Mitgliedschaft von `xkate578` in dieser Gruppe erlaubte es, das Passwort eines (indirekten) Domain Admins zu ändern.
*   **Exploitable AD-Pfad (via BloodHound/pywerview gefunden):** Kette von Gruppenmitgliedschaften (`xkate578` -> kann Passwort von `fbeth103` ändern; `fbeth103` in `Operators`; `Operators` in `Domain Admins`).
*   **NTDS.dit Dump:** Mit erlangten Domain-Admin-Rechten (indirekt über `fbeth103`) konnte die AD-Datenbank gedumpt werden, um alle Passwort-Hashes zu erhalten.
*   **Pass-the-Hash (PtH):** Wurde für den Domain-Administrator-Account verwendet, um vollen Zugriff auf den DC zu erhalten.

## Flags

*   **User Flag (`\\\\DC01\\share\\user.txt`):** `12f54a96f64443246930da001cafda8b`
*   **Root Flag (`C:\Users\Administrator\desktop\root.txt`):** `b8e59a7d4020792c412da75e589ff4fc`

## Tags

`HackMyVM`, `DC03`, `Medium`, `Active Directory`, `Windows`, `LLMNR Poisoning`, `Responder`, `Hash Cracking`, `John the Ripper`, `SMB`, `BloodHound`, `pywerview`, `Account Operators`, `Forced Password Change`, `bloodyAD`, `NTDS Dump`, `evil-winrm`, `Pass-the-Hash`, `Impacket`
