#!/usr/bin/env python3

from collections import Counter
import argparse
import binascii
import csv
import json
import os
import re
import statistics
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

#### Colours ####
# Formatting
Reset='\033[0m'         # Text Reset
Bold="\033[01;01m"      # Highlight

# Regular Colors
Yellow='\033[0;33m'     # Yellow
Green='\033[0;32m'      # Green

#### Functions Go Here ####

def parse_hex_values(password):
    matches = re.findall(r'\$HEX\[(.*?)\]', password)
    if len(matches) > 0:
        hex_string = matches[0]
        try:
            text = binascii.unhexlify(hex_string)
            decoded_text = text.decode("utf-8", errors="replace")
            return decoded_text  # Return the decoded text
        except Exception as e:
            print("Error decoding HEX:", e)
        return password
    else:
        return password

def extract_year(password):
    # Regular expression to match a year at the end of the password
    pattern = r'(20\d{2}|\d{2})$'
    match = re.search(pattern, password)
    return match.group() if match else None

year_counter = Counter()

def printLists(printDict, listType):
    sorted_list = sorted(printDict.items(), key=lambda kv: kv[1], reverse=True)
    print()
    print("Occurrences of " + str(listType) + " in passwords:")

    for Item in sorted_list:
        print(Item)

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", required=True, help="The path to hashcat output file to parse")
parser.add_argument("-k", "--keywords", required=False, help="Optional keywords to search for; comma separated, no spaces")
parser.add_argument("-o", "--output", required=False, help="Optional output directory path. Output will save to the same dir as script dir unless a path is provided.")
parser.add_argument("--html", action="store_true", help="Generate HTML output")
parser.add_argument("--json", action="store_true", help="Generate JSON output")
args = parser.parse_args()

month_list = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
season_list = ['Winter', 'Spring', 'Summer', 'Fall', 'Autumn']
colour_list = ['Red', 'Orange', 'Yellow', 'Green', 'Blue', 'White', 'Black', 'Purple', 'Violet', 'Rainbow', 'Gold', 'Silver']

if args.keywords:
    keywordList = [s.strip() for s in args.keywords.split(",")]

targetCounter = 0
passCounter = 0
longestPass = ""
shortestPass = None
longestPassSize = 0
shortestPassSize = float('inf')
lengthSum = 0
medianList = []

# Open the file in read mode
with open(args.input, "r") as text:
    # Create empty dictionaries
    d = dict()
    monthsDict = dict()
    seasonsDict = dict()
    colourDict = dict()
    keysDict = dict()
    year_list = [str(year) for year in range(1900, 2069)]
    yearsDict = dict()

    # Loop through each line of the file
    for line in text:
        passCounter += 1
        # Remove the leading spaces and newline character
        line = line.strip()

        # remove username and hash
        word = line.split(':', 3)
        password = word[2]

        password = parse_hex_values(password)

        year = extract_year(password)

        if year:
            year_counter[year] += 1

        # get the length of the password and add it to the variable to calculate mean average at the end
        lengthSum += len(password)
        medianList.append(len(password))

        # check password length and set the longest Password variable
        if len(password) > longestPassSize:
            longestPass = password
            longestPassSize = len(password)

        # check password length and set the shortest Password variable
        if shortestPass is None or len(password) < shortestPassSize:
            shortestPass = password
            shortestPassSize = len(password) if len(password) > 0 else 0

        # Check if the word is already in dictionary
        if password in d:
            # Increment count of word by 1
            d[password] += 1
        else:
            # Add the word to dictionary with count 1
            d[password] = 1

        top_years = sorted(yearsDict.items(), key=lambda kv: kv[1], reverse=True)[:10]
        for year in year_list:
            if year in password:
                if year in yearsDict:
                    yearsDict[year] += 1
                else:
                    yearsDict[year] = 1

        # loop through month list and see if the password contains a month, increments count if it does
        for month in month_list:
            if password.lower().find(month.lower()) != -1:
                if month in monthsDict:
                    monthsDict[month] += 1
                else:
                    monthsDict[month] = 1

        if args.keywords:
            for keys in keywordList:
                if password.lower().find(keys.lower()) != -1:
                    if keys in keysDict:
                        keysDict[keys] += 1
                    else:
                        keysDict[keys] = 1

        # loop through season list and and if the password contains a season, increments count if it does
        for season in season_list:
            if password.lower().find(season.lower()) != -1:
                if season in seasonsDict:
                    seasonsDict[season] += 1
                else:
                    seasonsDict[season] = 1

        # loop through colour list and and if the password contains a colour, increments count if it does
        for colour in colour_list:
            if password.lower().find(colour.lower()) != -1:
                if colour in colourDict:
                    colourDict[colour] += 1
                else:
                    colourDict[colour] = 1

# sort the password list based off count
sorted_x = sorted(d.items(), key=lambda kv: kv[1], reverse=True)
sorted_xLen = len(sorted_x)

print()

# print the top passwords
if sorted_xLen <= 10:
    print("The top " + str(sorted_xLen) + " passwords are:")
    for x in range(sorted_xLen):
        if sorted_x[x]:
            print(sorted_x[x])
else:
    print("The top 10 passwords are:")
    for x in range(10):
        if sorted_x[x]:
            print(sorted_x[x])

# print months, seasons, and keywords
printLists(monthsDict, "months")
printLists(seasonsDict, "seasons")
printLists(colourDict, "colours")

print("\nThe top 10 years in passwords are:")
for year, count in top_years:
    print(f"('{year}', {count})")

if args.keywords:
    printLists(keysDict, "keywords")

print()
print("Password Analysis Overview:")
print()
print("The longest password is: " + longestPass + " which is " + str(longestPassSize) + " characters")
print()
print("The shortest password is: " + shortestPass + " which is " + str(shortestPassSize) + " characters")
print()
print("Mean Average password length is " + str(round(lengthSum / passCounter)))
print()
median_length = round(statistics.median(medianList))
print("Median of password length is " + str(median_length))
print()
print("Total passwords cracked: " + str(passCounter))
print("\n")

##### Base Name & Output Dir #####

# Get the base name of the input file without the extension
input_file_basename = os.path.splitext(os.path.basename(args.input))[0]

# Determine the output directory
output_directory = args.output if args.output else os.path.dirname(args.input)

# Check if the user specified the output directory
if args.output:
    print(f"{Yellow}{Bold}Output directory specified:{Reset}\n {output_directory}\n")
    Path(args.output).mkdir(parents=True, exist_ok=True)
else:
    print("[!] No output directory specified. The output files will be saved in the same directory as the input file. [!]\n")

##### CSV File Creation & Output Path #####

# Specify the output CSV file path
output_csv_path = os.path.join(output_directory, f'{input_file_basename}_password_analysis_output.csv')

# CSV output (default output method)
print(f"{Yellow}{Bold}CSV output will be saved to:{Reset}\n {output_csv_path}")

# Open the CSV file in write mode
with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
    # Create a CSV writer
    csv_writer = csv.writer(csvfile)

    # Write additional information to the CSV file
    csv_writer.writerow(['Analysis Overview'])
    csv_writer.writerow(['Longest Password', longestPass, longestPassSize])
    csv_writer.writerow(['Shortest Password', shortestPass, shortestPassSize])
    csv_writer.writerow(['Mean Average Password Length', round(lengthSum / passCounter)])
    csv_writer.writerow(['Median of Password Length', median_length])
    csv_writer.writerow(['Total Passwords Cracked', passCounter])
    csv_writer.writerow([])  # Empty row for separation
    csv_writer.writerow(['Top 10 Passwords'])
    for x in range(min(10, sorted_xLen)):
        csv_writer.writerow(sorted_x[x])

    csv_writer.writerow([])  # Empty row for separation
    csv_writer.writerow(['Occurrences of Months in Passwords'])
    for month, count in monthsDict.items():
        csv_writer.writerow([month, count])

    csv_writer.writerow([])  # Empty row for separation
    csv_writer.writerow(['Occurrences of Seasons in Passwords'])
    for season, count in seasonsDict.items():
        csv_writer.writerow([season, count])

    csv_writer.writerow([])  # Empty row for separation
    csv_writer.writerow(['Occurrences of Colours in Passwords'])
    for colour, count in colourDict.items():
        csv_writer.writerow([colour, count])

    csv_writer.writerow([])  # Empty row for separation
    csv_writer.writerow(['Top 10 Years in Passwords'])
    for year, count in top_years:
        csv_writer.writerow([year, count])


##### JSON File Creation & Output Path #####

# Check if the user wants JSON output
if args.json:
    # Specify the output JSON file path
    output_json_path = os.path.join(output_directory, f'{input_file_basename}_password_analysis_output.json')

    # Check if the user wants JSON output
if args.json:
    print(f"\n{Yellow}{Bold}JSON output will be saved to:{Reset}\n {output_json_path}")

    # Create a dictionary for JSON output
    json_output = {
        "Analysis Overview": {
            "Longest Password": longestPass,
            "Shortest Password": shortestPass,
            "Mean Average Password Length": round(lengthSum / passCounter),
            "Median of Password Length": median_length,
            "Total Passwords Cracked": passCounter,
        },
        "Top 10 Passwords": sorted_x[:10],
        "Occurrences of Months in Passwords": monthsDict,
        "Occurrences of Seasons in Passwords": seasonsDict,
        "Occurrences of Colours in Passwords": colourDict,
        "Top 10 Years in Passwords": dict(top_years),
    }

    # Write JSON content to the file
    with open(output_json_path, 'w', encoding='utf-8') as jsonfile:
        json.dump(json_output, jsonfile, indent=2)

##### HTML File Creation & Output Path #####

# Check if the user wants HTML output
if args.html:
    # Specify the output HTML file path
    output_html_path = os.path.join(output_directory, f'{input_file_basename}_password_analysis_output.html')

    # Check if the user wants HTML output
if args.html:
    print(f"\n{Yellow}{Bold}HTML output will be saved to:{Reset} \n{output_html_path}\n")

    # Open the HTML file in write mode
    with open(output_html_path, 'w', encoding='utf-8') as htmlfile:

        environment = Environment(loader=FileSystemLoader("templates/"))
        template = environment.get_template("html_output.j2") 

        content = template.render(
            longestPass=longestPass,
            shortestPass=shortestPass,
            passCounter=passCounter,
            sorted_x=sorted_x,
            monthsDict=monthsDict,
            seasonsDict=seasonsDict,
            colourDict=colourDict,
            top_years=top_years,
            mean_password_length=round(lengthSum / passCounter),
            median_password_length=median_length
        )

    # Open the HTML file in write mode
    with open(output_html_path, 'w', encoding='utf-8') as htmlfile:
        htmlfile.write(content)

#### File Save Location Confirmation ####
print(f"[*] {Green}{Bold}Output Generated Successfully{Reset} [*]")
print()
