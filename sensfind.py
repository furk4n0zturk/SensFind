import requests
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)
import argparse
from pyfiglet import Figlet
from bs4 import BeautifulSoup

f = Figlet(font="standard")
print(f.renderText("SensFind") + "\n" + "Sensitive Web Path Finder v1.0 from @furk4n0zturk  - https://github.com/furk4n0zturk/")

class SensFind:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--url", "-u", help="Add to Target URL\n")
        parser.add_argument("--urllist", "-uL", help="Add to Target URL List\n")
        self.args = parser.parse_args()
        self.target_list = []
        self.getURL()
        self.getProduct()

    def getURL(self):

        if self.args.urllist == None:
            self.target_list.append(self.args.url)
        else:
            urlFile = open("{}".format(self.args.urllist))
            fileContent = urlFile.read()
            urllist = fileContent.splitlines()
            for url in urllist:
                self.target_list.append(url) 

    def getProduct(self):
        for self.target in self.target_list:
            self.product_filelist = ["sensitive-path.txt"]
            self.product_list = []

            if self.target[len(self.target) - 1] != "/":
                self.target += "/"
            try:
                self.target_req = requests.get(self.target, verify=False, allow_redirects=False, timeout=10)

                if "Tomcat" in self.target_req.headers["Server"] or "Coyote" in self.target_req.headers["Server"]:         
                    self.product_list.append("Apache-Tomcat")
                    self.product_filelist.append("tomcat.txt")

                if "Apache" in self.target_req.headers["Server"]:
                    self.product_list.append("Apache")
                    self.product_filelist.append("apache.txt")

                if "PHP" in self.target_req.headers["Server"]:
                    self.product_list.append("PHP")
                    self.product_filelist.append("php.txt")
                
                if len(self.product_list) == 0:
                    print("\nTarget: {}".format(self.target) + "\n[!] Detected Used Products: Not detect! Scanning sensitive files independent of the product\n")
                    self.productContent()
                else:
                    print("\nTarget: {}".format(self.target) + "\n[!] Detected Used Products: " + ', '.join(self.product_list)+"\n")
                    self.productContent()
            
            except requests.exceptions.ConnectionError as err:
                print("\n[!] Connection Error")
                pass
            except KeyError as err:
                pass
            except AttributeError as err:
                pass
            except requests.exceptions.ReadTimeout as err:
                print("\n[!] Connection Error")
                pass
            except requests.exceptions.InvalidURL as err:
                print("\n[!] Invalid URL Error")
                pass

    def productContent(self):

        if "Tomcat" not in self.product_list:
            source = BeautifulSoup(self.target_req.content,"lxml")

            if "Tomcat" in source:
                self.product_list.append("Tomcat")
                self.product_filelist.append("tomcat.txt")

        if "PHP" not in self.product_list:
            source = BeautifulSoup(self.target_req.content,"lxml")
            
            if "PHP" in source:
                self.product_list.append("PHP")
                self.product_filelist.append("php.txt")

        if "Apache" not in self.product_list:
            source = BeautifulSoup(self.target_req.content,"lxml")
            
            if "Apache" in source:
                self.product_list.append("Apache")
                self.product_filelist.append("apache.txt")
        self.fuzz()

    def fuzz(self):
        for product_forfile in self.product_filelist:
            self.product_file = product_forfile
            self.keyword_list = self.product_file

            if self.keyword_list == "php.txt":
                self.product = "PHP"
                
            if self.keyword_list == "apache.txt":
                self.product = "Apache"

            if self.keyword_list == "tomcat.txt":
                self.product = "Apache Tomcat"

            if self.keyword_list == "sensitive-path.txt":
                self.product = "NOT DETECT"

            self.file = open(self.keyword_list)
            content = self.file.read()
            list = content.splitlines()

            for path in list:
                try:
                    full_url = self.target + path
                    req = requests.get(full_url, verify=False, allow_redirects=False, timeout=10)
                    if req.status_code == 404 or req.status_code == 301 or req.status_code == 403:
                        pass
                    else:
                        print("[+] [{}] ".format(self.product) + "[{}] ".format(str(req.status_code)) + full_url)

                except requests.exceptions.ConnectionError as err:
                    print("\n[!] Connection Error")
                    pass
                except requests.exceptions.ReadTimeout as err:
                    print("\n[!] Connection Error")
                    pass
                except requests.exceptions.InvalidURL as err:
                    print("\n[!] Invalid URL Error")
                    pass
SensFind()

print("\nOK, Good Luck!")
