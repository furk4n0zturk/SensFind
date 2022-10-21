import requests
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)
import argparse
from pyfiglet import Figlet
from bs4 import BeautifulSoup

f = Figlet(font="standard")
print(f.renderText("SensFind") + "\n" + "Sensitive Web Path Finder v1.0 by @furk4n0zturk  - https://github.com/furk4n0zturk/")

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
		headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0','Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8','Accept-Language': 'tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3'}
                self.target_req = requests.get(self.target, headers=headers, verify=False, allow_redirects=False, timeout=10)

                if "tomcat" in self.target_req.headers["Server"] or "Coyote" in self.target_req.headers["Server"]:         
                    self.product_list.append("Apache-Tomcat")
                    self.product_filelist.append("tomcat.txt")

                if "Apache" in self.target_req.headers["Server"]:
                    self.product_list.append("Apache")
                    self.product_filelist.append("apache.txt")

                if "nginx" in self.target_req.headers["Server"]:
                    self.product_list.append("Nginx")
                    self.product_filelist.append("nginx.txt")

                if "PHP" in self.target_req.headers["Server"]:
                    self.product_list.append("PHP")
                    self.product_filelist.append("php.txt")
                
                if "Wordpress" in self.target_req.headers["Server"]:
                    self.product_list.append("Wordpress")
                    self.product_filelist.append("php.txt")
                
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
	web_content = self.target_req.content.lower()
	
        if "Tomcat" not in self.product_list:
            source = str(BeautifulSoup(web_content,"lxml"))

            if "tomcat" in source:
                self.product_list.append("Tomcat")
                self.product_filelist.append("tomcat.txt")

        if "PHP" not in self.product_list:
            source = str(BeautifulSoup(web_content,"lxml"))
            
            if "php" in source:
                self.product_list.append("PHP")
                self.product_filelist.append("php.txt")

        if "Apache" not in self.product_list:
            source = str(BeautifulSoup(web_content,"lxml"))
            
            if "apache" in source:
                self.product_list.append("Apache")
                self.product_filelist.append("apache.txt")

        if "Nginx" not in self.product_list:
            source = str(BeautifulSoup(web_content,"lxml"))
            
            if "nginx" in source:
                self.product_list.append("Nginx")
                self.product_filelist.append("nginx.txt")

        if "WordPress" not in self.product_list:
            source = str(BeautifulSoup(web_content,"lxml"))
		
            if "wordpress" in source:
                self.product_list.append("Wordpress")
                self.product_filelist.append("wordpress.txt")

        if len(self.product_list) == 0:
            print("\nTarget: {}".format(self.target) + "\n[!] Detected Used Products: Not detect! Scanning sensitive files independent of the product\n")
            self.fuzz()
        else:
            print("\nTarget: {}".format(self.target) + "\n[!] Detected Used Products: " + ', '.join(self.product_list)+"\n")
            self.fuzz()
            
    def fuzz(self):
        for product_forfile in self.product_filelist:
            self.product_file = product_forfile
            self.keyword_list = self.product_file

            if self.keyword_list == "php.txt":
                self.product = "PHP"

            if self.keyword_list == "nginx.txt":
                self.product = "NGINX"
                
            if self.keyword_list == "apache.txt":
                self.product = "Apache"

            if self.keyword_list == "tomcat.txt":
                self.product = "Apache Tomcat"

            if self.keyword_list == "wordpress.txt":
                self.product = "Wordpress"

            if self.keyword_list == "sensitive-path.txt":
                self.product = "NOT DETECT"

            self.file = open("src/"+self.keyword_list)
            content = self.file.read()
            list = content.splitlines()

            for path in list:
                try:
                    full_url = self.target + path
		    headers2 = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0'}
                    req = requests.get(full_url,headers=headers2, verify=False, allow_redirects=False, timeout=10)
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
