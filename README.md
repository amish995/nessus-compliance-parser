# nessus-compliance-parser
Python script to parse Nessus policy compliance XML files to excel.

## Usage
```(shell)
pip3 install -r requirements.txt
python3 nessus-compliance-parser-v3.py input1.nessus input2.nessus ...
```
## Limitations
- Multiple files with the same host IPs need to be handled separately. If run together, the script will only export the results of the final file ingested
- Warnings and Error outputs are both processed as "WARNING"

## TODO
- Conditional formatting for the cells based on status
  - Passed : Green Cell Background
  - Failed : Red Cell Background
  - Warning : Yellow Cell Background
