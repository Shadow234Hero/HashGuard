# Cryptojacking Detector

A Windows desktop project for investigating possible unauthorized cryptocurrency mining. The dashboard links CPU or GPU activity to a particular running program, examines its executable and network peers, and explains the evidence behind each finding.

## Run on your laptop

1. Extract the **whole ZIP** into a folder where you can save files, such as Downloads.
2. Open that folder and double-click **Start-Detector.pyw**. If Windows opens an editor instead, open PowerShell in the same folder and run **py detector.py --gui**.
3. Click **Run demo**. After about five seconds the Findings tab shows **Video export → Sustained load** and **Simulated miner → Mining indicators**. Select each row to compare the evidence.
4. Click **Start live** for your own laptop. Choose a row in Processes and click **Inspect selected process**. The result appears in Findings after Windows finishes the queries. Use **Stop** to stop collecting samples.

Python 3.11 or newer with Tkinter runs the desktop app. Live mode needs psutil 6.0 or newer. If necessary run **py -m pip install "psutil>=6"** in PowerShell. The offline demo needs only Python with Tkinter. The project also retains the terminal commands **py detector.py** for live monitoring and **py detector.py --demo** for simulation.

## Prepare a two-minute presentation

| Step | Show | Explain |
|---|---|---|
| 1 | Run demo, then select Video export | A genuine computation can stay above the CPU threshold. The detector records the load. |
| 2 | Select Simulated miner | The same CPU pattern has additional evidence: a Stratum text marker and a simulated pool destination. |
| 3 | Click Quarantine demo, confirm, then click it again to restore | An actual harmless text file moves to a private training folder and returns to its original path. |
| 4 | Start live and inspect a process you recognize | Show its real executable path and observed TCP peers. Read the coverage notes if access is limited. |

For your viva: “The tool identifies mining indicators. To decide whether observed mining is cryptojacking, we also need to know whether the device owner authorized it.”

See **PROJECT-REPORT.md** for the architecture, rule definitions, test results and limits. The report includes the tested dashboard screenshot.

## Evidence and review actions

- Live alerts append to **alerts.csv** and **alerts.jsonl** beside the script. The CSV uses the original five columns. JSONL retains the full evidence for each finding. **process_reviews** files contain manually requested reviews. **demo_alerts** files contain simulated findings.
- A process list is a one-second view. Click a process and inspect it to see its path, file markers, SHA-256 approval status, publisher signature, established TCP peers and directly matching startup entries.
- **Approve this file hash** mutes repeat load-only alerts for the same executable contents. A change to the file invalidates its approval. Manual reviews and findings with mining indicators stay visible.
- **Review actions** can request a Microsoft Defender scan or a confirmed stop of the selected user application. Defender applies the local Windows policy to detected threats. Open **Windows Security → Virus & threat protection → Protection history** to review quarantine, removal or restoration as available.
- **Review matching startup entries** lists launch entries targeting the same executable. With sufficient Windows permissions and explicit confirmation, the app can disable an exact task or service or back up and remove a matching Run value. Multi-action scheduled tasks require manual review. Windows tools can also be opened directly from this dialog.
- Startup changes save backups under **%LOCALAPPDATA%\CryptojackingDetector\startup-backups**. A task backup is exported task XML. Service backup fields record the service name and prior startup mode. Registry backups are PowerShell CLIXML containing the key, name, original value and kind. Restore an approved task or service using Task Scheduler or Services. To restore a Run value, review its saved fields in the XML and recreate that original value and type in Registry Editor.
- A protected process can return **Access denied**. A missing GPU counter or unavailable DNS cache is reported as a coverage gap. The app can run as a standard Windows user.

## Project files

| File | Role |
|---|---|
| detector.py | Terminal entry point, CPU and GPU rules, pool connection polling, logging and offline demo |
| dashboard.py / Start-Detector.pyw | Tkinter desktop window and launcher |
| evidence.py | Same-process file and network analysis, checksums and finding classification |
| tools/windows.ps1 | Windows GPU counters, DNS cache, Authenticode, startup review and Defender integration |
| pools.json | Editable exact pool hostnames and dedicated IP addresses |
