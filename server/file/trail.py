from . import hashlib
import io
import os
import requests

def sum():
    return 7

def hash_value(name):

    with io.open(name, mode="rb") as fd:
        content = fd.read()
        md5 = hashlib.md5(content).hexdigest()
        return md5


def convert_bytes(num):
    """
    this function will convert bytes to MB.... GB... etc
    """
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0


def file_size(file_path):
    """
    this function will return the file size
    """
    if os.path.isfile(file_path):
        file_info = os.stat(file_path)
        return convert_bytes(file_info.st_size)

def VT_Request(key, hash,f):

        if len(key) == 64:
            try:
                params = {'apikey': key, 'resource': hash }
                url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                json_response = url.json()
                # print json_response

                response = int(json_response.get('response_code'))
                if response == 0:
                    print ('[-] ' + f + ' [' + hash + '] is not in Virus Total')
                    file = open('VT Scan.txt', 'a')
                    file.write('[-] ' + f + ' [' + hash + '] is not in Virus Total')
                    file.write('\n')
                    file.close()
                elif response == 1:
                    positives = int(json_response.get('positives'))
                    if positives == 0:
                        print ('[-] ' + f + ' [' + hash + '] is not malicious')
                        file = open('VT Scan.txt', 'a')
                        file.write('[-] ' + f + ' [' + hash + '] is not malicious')
                        file.write('\n')
                        file.close()
                        return "not malicious"
                    else:

                        sha1 = json_response.get('sha1')
                        md5=json_response.get('md5')
                        positives = int(json_response.get('positives'))
                        total = int(json_response.get('total'))
                        sha256 = json_response.get('sha256')

                        scans = str(json_response.get('scans'))

                        print ('\n [*] Malware Hit Count ' + str(positives) + '/' + str(total))
                        print ('\n [*] Sha1 Value = ' + sha1)
                        print ('\n [*] Sha256 Value = ' + sha256)

                        # print '\n Scans = ' + str(scans)

                        print ('\n [*] ' + f + ' [' + hash + ']' + ' is malicious')
                        file = open('VT Basic Scan.txt', 'a')
                        file.write('[*] ' + f + ' [' + hash + '] is malicious.')
                        file.write('\n\n')
                        file.write('\n[*] Malware Hit Count ' + str(positives) + '/' + str(total))
                        file.write('\n[*] MD5 Value = ' + md5)
                        file.write('\n[*] Sha1 Value = ' + sha1)
                        file.write('\n[*] Sha256 Value = ' + sha256)
                        file.write('\n\n')
                        file.close()
                        file = open('VT Scan.csv', 'a')
                        file.write('AV Name,Detection,AV Version,Malware Name,AV Updated Date')
                        file.write('\n')
                        file.write(str(scans).replace('}, u', '\n').replace(' u', '').replace('{', '').replace(': u',
                                                                                                               ' = ').replace(
                            "'", "").replace('}}', '').replace(' = detected: ', ',').replace('result:', '').replace(
                            'update:', '').replace('uBkav', 'Bkav') + '\n')
                        file.write('\n')
                        file.close()
                        return [md5,sha1,sha256,positives,total]
                else:
                    print (hash + ' [-] could not be searched. Please try again later.')
                print ('\n\n *******************')
                print (' * See VT Scan.csv *')
                print (' *******************')
            except Exception:
                print ('\n [-] Oops!!, Somthing Wrong Check Your Internet Connection')
        else:
            print (" [-] There is something Wrong With Your API Key.")
            exit()


