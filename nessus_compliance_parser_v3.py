#!/usr/bin/env python3
# Last Updated -- 03 Feb 2026
# Description -- Creates an excel with a summary of compliance issues, and 
# an excel sheet for every IP with the corresponding compliance issues. 

# imports
import argparse
import xml.etree.ElementTree as ET
import xlsxwriter
import re

WKS_HEADERS = ['Check', 'Result', 'Description', 'Policy Value', 'Actual Value', 'Remediation', 'Profile', 'Reference']
SUMM_HEADERS = ['No.', 'IP', 'Benchmark', 'Passed', 'Failed', 'Warning', 'Total']

IGNORED_COMPLIANCE_CHECKS = ['CIS_Ubuntu_20.04_LTS_Server_v1.1.0_L1.audit from CIS Ubuntu Linux 20.04 LTS Benchmark']

# Tags to get from each issue item
COMPLIANCE_TAGS = ['{http://www.nessus.org/cm}compliance-check-name', '{http://www.nessus.org/cm}compliance-result', '{http://www.nessus.org/cm}compliance-info', '{http://www.nessus.org/cm}compliance-policy-value', '{http://www.nessus.org/cm}compliance-actual-value', '{http://www.nessus.org/cm}compliance-solution', '{http://www.nessus.org/cm}compliance-benchmark-profile', '{http://www.nessus.org/cm}compliance-see-also']

# COMPLIANCE_TAGS = ['{http://www.nessus.org/cm}compliance-check-name', '{http://www.nessus.org/cm}compliance-result', '{http://www.nessus.org/cm}compliance-info', '{http://www.nessus.org/cm}compliance-solution', '{http://www.nessus.org/cm}compliance-see-also']


def get_total(ip_summary):
    '''
    Returns total number of compliance checks for an IP

    Args:
        ip_summary: a list of [passed, failed, warning]
            checks for an IP.
    Returns:
        Sum of count of passed, failed and warning
    '''
    # return passed + failed + warning
    return ip_summary[1] + ip_summary[2] + (ip_summary[3]+ip_summary[4])


def write_excel_report(workbook_name, summary_dict, issues_dict, font='IBM Plex Sans'):
    '''
    Writes a compliance report containing the issues identified

    Given the workbook name, the dictionaries containing the summary 
    of issues, and all the compliance issues for all the IPs, and 
    the font, writes the output in a formatted manner.

    Args:
        workbook_name: name of the output workbook
        summary_dict: a dictionary of {IP: [num_passed, num_failed,
             num_warning]}
        issues_dict: a dictionary of {IP: [Issue1, Status1, Description1, 
            Result1, Solution1, See Also1], [Issue2, Status2, Description2, 
            Result2, Solution2, See Also2]}
    '''

    # Initialize the workbook and cell styling
    wb = xlsxwriter.Workbook(workbook_name)
    title_format = wb.add_format({'bold': True, 'font_color':'white', 'font_name':'IBM Plex Sans', 'bg_color':'black','border':1, 'font_size':10, 'text_wrap':True, 'align':'left', 'valign':'top'})

    normal_format = wb.add_format({'font_name':'IBM Plex Sans', 'border':1, 'font_size':10, 'text_wrap':True, 'align':'left', 'valign':'top'})
    
    # Write the summary sheet
    # first  write the headers
    summ = wb.add_worksheet("Summary")
    for i in range(0, len(SUMM_HEADERS)):
        summ.write(0, i, SUMM_HEADERS[i], title_format)
        summ.set_column(0,i,20) 
    # Then write the rows: IP, passed, failed, warning, total
    row = 1
    for ip in summary_dict.keys():
        summ.write(row, 0, row, normal_format)
        summ.write(row, 1, ip, normal_format)
        # passed, failed, warning
        for j in range(len(summary_dict[ip])):
            summ.write(row, j+2, summary_dict[ip][j], normal_format)
        # total
        summ.write(row, 6, get_total(summary_dict[ip]), normal_format)
        row += 1

    # For every IP, write a new sheet containing all the issues
    # Each sheet will have the columns: Check, Status, Description, 
    # Result, Solution, See Also
    for ip_address in issues_dict:
        ip_issues = wb.add_worksheet(f'{ip_address} Issues')

        # First, init and add headers for the sheet
        for i in range(0, len(WKS_HEADERS)):
            ip_issues.write(0, i, WKS_HEADERS[i], title_format)
            ip_issues.set_column(i,i,int(len(WKS_HEADERS[i])*1.3))

        # set formatting for specific columns
        ip_issues.set_column(0,0,30) 
        ip_issues.set_column(2,2,80)  
        ip_issues.set_column(3,3,50)
        ip_issues.set_column(4,4,50)
        ip_issues.set_column(5,5,35)
        ip_issues.set_column(7,7,40)

        # Write the issues
        row = 1
        for issue_list in issues_dict[ip_address]:
            for i in range(len(issue_list)):
                ip_issues.write(row, i, issue_list[i], normal_format)
            row += 1
    
    wb.close()
    print("Done writing to workbook!")


def get_value(rawValue):
    '''
    Clean values from nessus tag by removing
    new lines and limiting text to 32000 characters
    '''
    # Replace the new lines so that it doesnt mess up anything else
    cleanValue = rawValue.replace('\n', '\t').strip(' ')
    # Praise our lord and savior, Regex
    # Removes all the multiple spaces between words that Nessus randomly adds 
    cleanValue = re.sub(' {2,}', ' ', cleanValue)
    if len(cleanValue) > 32000:
        cleanValue = cleanValue[:32000] + ' [Text Cut Due To Length]'
    return cleanValue


# Handle a single Report Host
def handle_report(report):
    '''
    Given a report for a single IP, extract all the issues

    Args:
        report: the report for a single report host containing
            multiple ReportItem objects

    Returns:
        ip_issues: a list of lists containing the necessary compliance
            tags for each of the issues in the report.
        summary_counts: a list of [passed, failed, warning] counts
            for the IP            
    '''
    summary_dict = {'FAILED': 0, 'PASSED': 0, 'WARNING': 0, 'ERROR':0}
    ip_issues = []
    benchmark_name = ''

    # Go thru all the 'issue' items that have severity not 0 
    for item in report.findall('ReportItem'):
        # if item.attrib['severity'] != "0":
        # Go through report item and extract the 
        # necessary compliance tags
        issue_dict = {elem.tag: get_value(elem.text) for elem in item if elem.tag in COMPLIANCE_TAGS}

        # Set benchmark name for summary sheet
        if len(ip_issues) == 1 and benchmark_name == '':
            benchmark_name = item.find('{http://www.nessus.org/cm}compliance-benchmark-name').text + ' v' + item.find('{http://www.nessus.org/cm}compliance-benchmark-version').text

        # Count issue status for summary and convert issue dict to list
        # Skipping error tags

        # one way to filter:
        # if(issue_dict != {} and issue_dict['{http://www.nessus.org/cm}compliance-result'] != 'ERROR' and issue_dict['{http://www.nessus.org/cm}compliance-check-name'] not in IGNORED_COMPLIANCE_CHECKS):
        # alternatively, check that length of issues = length of compliance tags
        if '{http://www.nessus.org/cm}compliance-actual-value' not in issue_dict.keys():
            issue_dict['{http://www.nessus.org/cm}compliance-actual-value'] = 'No output recorded'
        if len(issue_dict.keys()) == len(COMPLIANCE_TAGS):
            summary_dict[issue_dict['{http://www.nessus.org/cm}compliance-result']] += 1
            try:
                issue_list = [issue_dict[tag] for tag in COMPLIANCE_TAGS]
            except KeyError as e:
                print(issue_dict.keys())
            ip_issues.append(issue_list)
    
    summary_counts = [benchmark_name, summary_dict['PASSED'], summary_dict['FAILED'], summary_dict['WARNING'], summary_dict['ERROR']]

    return ip_issues, summary_counts 
     

if __name__ == '__main__':

    aparser = argparse.ArgumentParser(description='Converts Nessus scan findings from XML to an Excel file with a summary tab. Consolidates IPs with the same issue into 1 row', usage="\n./nessus-compliance-parser-v3.py input1.nessus input2.nessus ...\nAny fields longer than 32,000 characters will be truncated.")
    aparser.add_argument('nessus_xml_files', type=str, nargs='+', help="nessus xml file to parse")
    aparser.add_argument('--out', type=str, help="output workbook to save results in", default="Compliance_Summary.xlsx")

    args = aparser.parse_args()
    nessus_xml, output_wb = args.nessus_xml_files, args.out

    # Initialize the dictionaries that consolidate everything
    summary_dict = dict() 
    ip_issues_dict = dict() 

    # For each .nessus file, handle the report items 
    for nessusScan in nessus_xml:
        try:
            scanFile = ET.parse(nessusScan)
        except IOError:
            print("Could not find file \"" + nessusScan + "\"")
            exit()
        xmlRoot = scanFile.getroot()
        # Handle each IP inside a report
        for report in xmlRoot.findall('./Report/ReportHost'):
            ip_address = report.find("HostProperties/tag/[@name='host-ip']").text
            print(f"Extracting issues for IP {ip_address}")
            res, summary_res = handle_report(report)
            ip_issues_dict[ip_address] = res
            summary_dict[ip_address] = summary_res
    
    write_excel_report(output_wb, summary_dict, ip_issues_dict, 'IBM Plex Sans')
    
    print("Done!")