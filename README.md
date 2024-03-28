# Cryptanalysis
Takes the output of Hashcat pot file and does some basic stats and cryptanalysis e.g., frequency analysis.

`cryptanalysis.py` Expects the content format of the supplied dit file to look like this:

**\<username\>:\<hash\>:\<password\>** e.g., `bob:b4b9b02e6f09a9bd760f388b67351e2b:hashcat`

## Installation
**Simply clone or download the repo, then:**

```text
cd Cryptanalysis
pip install -r requirements.txt
python3 cryptanalysis.py -h
```
**Successful install will return in the display of the 'Help Menu'**

## Help Menu:
```
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        The path to hashcat output file to parse
  -k KEYWORDS, --keywords KEYWORDS (OPTIONAL)
                        optional keywords to search for; comma seperated, no
                        spaces
  -o Output Location, --output Output Location
                        optional output directory path. Output will save to the same dir as script dir unless a path is provided
  --html                generate HTML output. Output will save to the same dir as script dir unless a path is provided
  --json                generate JSON output. Output will save to the same dir as script dir unless a path is provided
```
_Note: `-i` flag is complusory. When no other cmd line flags are intput/specified, only terminal output and a default CSV will be returned._

## Tool Usage & Examples Commands:

**No CMD Line flags:**
```text
python3 cryptanalysis.py -i /path/to/your/dit/cracked/dir.txt
```
_Note: A CSV file is generated by default and output to the same dir as the script is run from. Use the -o flag to output to a different location_

**Just the basics: Terminal output and default CSV file to your chosen location:**
```text
python3 cryptanalysis.py -i /path/to/your/dit/cracked/dir.txt -o /path/to/your/choosen/output/dir/
```
**Just a little bit more: Terminal output, default CSV file and HTML file  to your chosen location:**
```text
python3 passfreq.py -i /path/to/your/dit/cracked/dir.txt -o /path/to/your/choosen/output/dir/ --html
```
**Give me more: Terminal output, default CSV file, HTML file and JSON file to your chosen location:**
```text
python3 cryptanalysis.py -i /path/to/your/dit/cracked/dir.txt -o /path/to/your/choosen/output/dir/ --json --html
```
