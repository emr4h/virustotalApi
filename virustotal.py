import argparse
from pyfiglet import Figlet
import random
import subprocess
import requests

print("\n\n\n")

fontList = ["big","bulbhead","roman","epic","larry3d","speed","nancyj","stampatello","smslant","slscript","serifcap","rounded","puffy","o8","letters","colossal","basic"]
fontType = random.choice(fontList)
f = Figlet(font=fontType)
print(f.renderText('VirusTotal Api'))

print("by emr4h\n")

parser = argparse.ArgumentParser(prog="virustotalApi\n", description="Virustotal API", usage="\n\n Hash Analysis with Virus Total: python3 virustotal.py -p <file_path> \n ")
parser.add_argument("-p","--path", help = "Path of the file to be analyzed")
args = parser.parse_args() 

def hashVirusTotal(file):

    hash = subprocess.check_output(["md5",file]) 
    hash = hash.split()
    hash = hash[3]
    hash = hash.decode() 

    fileHash = str(hash)
    params = {}
    apiKey = input("\nIf you have a virustotal account, please enter your apikey, you can find your apikey in your profile for free (recommended). \nIf you don't have the apikey proceed without entering anything. A default apikey will be used, but since this key is free, it may be subject to query limitations. \nPlease Enter Your API Key : ")
    
    if(apiKey == ""):
        params = {'apikey': "464660c9da6e6cfd9edc41d92d354f7b8b3bfdd76a01d6cfdabc46d6a575bb3b", 'resource': fileHash}
    else :
        apiKey = str(apiKey)
        params = {'apikey': apiKey, 'resource': fileHash}

    responseData = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)

    jsonData = responseData.json()
    responseData = int(jsonData.get('response_code'))

    if(responseData == 0):
        print ('\nThe file with the ' + fileHash + ' hash number was not found in virustotal\n')
    elif(responseData == 1):
        if(int(jsonData.get('positives'))) == 0:
            print ('\nThe file with the ' + fileHash + ' is not a malware\n')
        else:
            print ('\nThe file with the ' + fileHash + ' is a malware\n')
    else:
        print('\nThe hash could not be searched. Please try again later.\n')

if __name__=='__main__':
    if(args.path):
        hashVirusTotal(args.path)