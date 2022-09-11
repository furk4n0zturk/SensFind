# SensFind - Sensitive Web Path Finder v1.0

Detects Web products used at the given URL. Searches sensitive files according to the detected product. Prints the sensitive files found to the screen as output

## Features

1. Specify URL or URL list as input
2. Detects products used at addresses specified as input
3. It searches sensitive indexes according to the product used on the Web Sites.
4. Searches for sensitive directories that are often found on websites
5. Prints the detected sensitive directories to the screen as output
6. Good Luck!

Products that can be detected in this version:
- Nginx
- Apache
- Apache Tomcat
- WordPress
- PHP

Scans for potentially sensitive directories on a website even if the product is not detected.

## Usage

```
git clone https://github.com/furk4n0zturk/SensFind.git
```
```
cd SensFind
```
```
pip install -r requirements.txt
```
View available parameters
```
$ python sensfind.py -h
 ____                 _____ _           _
/ ___|  ___ _ __  ___|  ___(_)_ __   __| |
\___ \ / _ \ '_ \/ __| |_  | | '_ \ / _` |
 ___) |  __/ | | \__ \  _| | | | | | (_| |
|____/ \___|_| |_|___/_|   |_|_| |_|\__,_|


Sensitive Web Path Finder v1.0 by @furk4n0zturk  - https://github.com/furk4n0zturk/
usage: sensfind.py [-h] [--url URL] [--urllist URLLIST]

optional arguments:
  -h, --help            show this help message and exit
  --url URL, -u URL     Add to Target URL
  --urllist URLLIST, -uL URLLIST
                        Add to Target URL List

```
To specify a single URL use the command
```
python sensfind.py -u https://example.com
```
To specify a list of URLs, use the command
```
python sensfind.py -uL url_list.txt
```
