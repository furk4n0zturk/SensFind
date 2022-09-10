import requests
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)
import argparse
from pyfiglet import Figlet
import builtwith

f = Figlet(font="standard")
print(f.renderText("SensFind") + "\n" + "Sensitive Web Path Finder v1.0 from @furk4n0zturk  - https://github.com/furk4n0zturk/ \n")

product = "TOMCAT"

class SensFind:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--url", "-u", help="Add to Target URL\n")
        self.target = parser.parse_args().url
        if self.target[len(self.target) - 1] != "/":
            self.target += "/"
        self.product()
        self.fuzz()

    def product(self):
        pro = builtwith.parse(self.target)
        print(pro)

        if product == "PHP":
            self.keyword_list = "php.txt"

        if product == "TOMCAT":
            self.keyword_list = "tomcat.txt"
        else:
            print("Err")

    def fuzz(self):
        self.file = open(self.keyword_list)
        content = self.file.read()
        list = content.splitlines()

        for path in list:
            full_url = self.target + path
            req = requests.get(full_url, verify=False, allow_redirects=False)
            if req.status_code == 404 or req.status_code == 301 or req.status_code == 403:
                pass
            else:
                print("[+] [{}] ".format(product) + full_url + " = " + str(req.status_code))

SensFind()

print("\n")
print("OK, Good Luck!")