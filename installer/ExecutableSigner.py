import os.path
import subprocess
import sys

tool_file_name             = sys.argv[2] + '\signtool.exe'
target_file_name           = sys.argv[1]
sign_cert_file_name        = '..\windows\SignCertFile.p12'
sign_cert_passwd_file_name = '..\windows\SignCertPasswdFile.txt'

print('ExecutableSigner');
if os.path.isfile(target_file_name) and                                     \
   os.path.isfile(sign_cert_file_name) and                                  \
   os.path.isfile(sign_cert_passwd_file_name):
    print('Siging');
    with open(sign_cert_passwd_file_name, 'r') as sign_cert_passwd_file:
        sign_cert_passwd = sign_cert_passwd_file.read().replace('\n', '')
        subprocess.call(                                                    \
            [sys.argv[2] + '\signtool.exe', 'sign', '/t',                                  \
             'http://timestamp.digicert.com', '/f', sign_cert_file_name,    \
             '/fd', 'sha256', '/p', sign_cert_passwd, target_file_name])
