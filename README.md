# nessus-compliance-parser
Python script to parse Nessus policy compliance XML files to excel.

## Usage
```(shell)
pip3 install -r requirements.txt
python3 nessus-compliance-parser-v3.py -xml input1.nessus input2.nessus ...
```

## Notes
- The script will output a summary sheet with excel formulas for the counts (PASSED, FAILED, NA).
- Manual updates to the status on each worksheet will automatically update the summary sheet. Use "NA" for checks that are to be counted as excluded.
- 

## Limitations
- Multiple files with the same host IPs need to be handled separately. If run together, the script will only export the results of the final file ingested
- Warnings and Error outputs are both processed and reported in the sheets as "WARNING"

## TODO
- Conditional formatting for the cells based on status
  - PASSED : Green Cell Background
  - FAILED : Red Cell Background
  - NA : Yellow Cell Background
