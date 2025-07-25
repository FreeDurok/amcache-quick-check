# amcache-quick-check.sh

This Bash script extracts SHA1 hashes of `.exe` files listed in an Amcache inventory file (typically exported from Windows systems) and automatically checks them against [VirusTotal](https://www.virustotal.com/) using the public API.

## Features

- Extracts file paths and SHA1 hashes of `.exe` files from the Amcache file.
- **Only considers files with missing metadata (e.g., missing company information).** Generally, trusted files have properly filled metadata.
- Allows filtering to only files located in user folders (`users`) or across the entire system.
- Queries the VirusTotal API for each extracted hash and displays the analysis results (malicious, suspicious, harmless, undetected).
- Highlights results with colors for easier reading.

## Requirements

- An output file generated by [Volatility3](https://volatility3.readthedocs.io/en/latest/Installation.html) using the `amcache` module :    
- [jq](https://stedolan.github.io/jq/) installed
- [curl](https://curl.se/) installed
- A VirusTotal API key (edit the `API_KEY` variable in the script if needed)

## Installing Required Packages

On Ubuntu (or Debian-based systems):

```sh
sudo apt update
sudo apt install jq curl
```

```sh
brew install jq curl
```

## Installing and Running Volatility

To analyze a memory dump and extract the Amcache inventory, you need to install Volatility3.

### Install Volatility3

On Ubuntu (or Debian-based systems):
```sh
sudo apt update
sudo apt install python3-pip git python3-venv
python3 -m venv venv
source venv/bin/activate
pip install volatility3
```

### Extract Amcache Data from a Memory Dump

Run the following command to extract the Amcache data:

```sh
vol -f memdump.mem windows.registry.amcache.Amcache > amcache.txt
```

- Replace `memdump.mem` with the path to your memory dump file.
- The output (`amcache.txt`) can then be used as input for this script.

## Usage

```sh
./amcache-quick-check.sh [--scope users|system] [--json-output yes|no] <amcache_file.txt>
```

- `--scope users` : analyzes only `.exe` files in user folders (`C:\Users\...`)
- `--scope system` (default): analyzes all `.exe` files present in the Amcache file
- `--json-output yes` : outputs the results in JSON format
- `--json-output no` (default): outputs the results in a human-readable format

Example:

```sh
./amcache-quick-check.sh --scope users --json-output yes amcache.txt
```
## Output

For each file found, the script displays:

- The file path
- The SHA1 hash
- The VirusTotal analysis results (Harmless, Suspicious, Malicious, Undetected)

## Screenshot

![Screenshot of amcache-quick-check.sh output](.img/amcache1.png)

---

**Note:**
- **Only files with missing metadata (such as company information) are considered for analysis, as these are more likely to be untrusted or suspicious.**
- Only files with a valid SHA1 hash are processed.
