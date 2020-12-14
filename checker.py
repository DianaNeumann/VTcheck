import sys
import argparse
import json
import requests
import hashlib
from termcolor import colored
import colorama
colorama.init()

API_KEY = 'ВАШ API KEY (str)'

# parser = argparse.ArgumentParser(description='#')
# parser.add_argument('file_name', help="#")
# args = parser.parse_args()
# file_name = args.file_name

def check_hash():
    with open(str(sys.argv[1]), 'rb') as file:
        buffer = file.read()
        print('*')
        print(colored('md5 = ' + hashlib.md5(buffer).hexdigest(), 'white'))
        print(colored('sha1 = ' + hashlib.sha1(buffer).hexdigest(), 'blue'))
        print(colored('sha256 = ' + hashlib.sha256(buffer).hexdigest(), 'red'))
        print('*')

check_hash()

def is_already_scan():
    api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = dict(apikey=API_KEY, resource=str(sys.argv[1]))
    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            print('Обнаружено:', result['positives'], '/', result['total'])
            print('Результаты сканирования:')
            for key in result['scans']:
                print('\t' + key, '==>', result['scans'][key]['result'])
        elif result['response_code'] == -2:
            print('Объект в очереди на анализ.')
        elif result['response_code'] == 0:
            print('Объект отсутствует в базе VirusTotal.')
        else:
            print('Ошибка ответа VirusTotal')
    else:
       print('Ошибка ответа VirusTotal') 


def send_file():
    api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = dict(apikey=API_KEY)
    with open(file_name, 'rb') as file:
        files = dict(file=(file_name, file))
        response = requests.post(api_url, files=files, params=params)
    if response.status_code == 200:
        result = response.json()
        print(json.dumps(result, sort_keys=False, indent=4))


def receive_file_info():
    api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = dict(apikey=API_KEY, resource=' SOME FILE ID')
    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        result = response.json()
        for key in result['scans']:
            print( '[' + colored(key, 'cyan') + ']')
            print('    Detected: ', result['scans'][key]['detected'])
            print('    Version: ', result['scans'][key]['version'])
            print('    Update: ', result['scans'][key]['update'])
            print('    Result: ', result['scans'][key]['result'])


def send_url():
    api_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = dict(apikey=API_KEY, 
    url='https://www.hackthissite.org')

    response = requests.post(api_url, data=params)
    if response.status_code == 200:
        result = response.json()
        print(json.dumps(result, sort_keys=False, indent=4))


def receive_url_info():
    api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = dict(apikey=API_KEY,
    resource='https://www.hackthissite.org')
    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        result = response.json()
        for key in result['scans']:
            print( '[' + colored(key, 'cyan') + ']')
            print('    Detected: ', result['scans'][key]['detected'])
            print('    Result: ', result['scans'][key]['result'])

def send_ip():
    api_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = dict(apikey=API_KEY,
    domain='fotoforensics.com')
    response = requests.get(api_url, params)
    if response.status_code == 200:
        result = response.json()
        print(json.dumps(result, sort_keys=False, indent=4))

def receive_ip_info():
    api_url = 'https://www.virustotal.com/vtapi/v2/domain/report'   
    params = dict(apikey=API_KEY,
    domain='fotoforensics.com')    
    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        result = response.json()
        print(json.dumps(result, sort_keys=False, indent=4))
