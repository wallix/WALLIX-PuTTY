import os.path
import subprocess
import time

target_file_name           = 'Release\iploop.exe'
sign_cert_file_name        = '..\..\SignCertFile.p12'
sign_cert_passwd_file_name = '..\..\SignCertPasswdFile.txt'

if not os.path.isfile(target_file_name):
    print('not target_file_name');
else:
    print('target_file_name');

if os.path.isfile(target_file_name) and                                     \
   os.path.isfile(sign_cert_file_name) and                                  \
   os.path.isfile(sign_cert_passwd_file_name):
    print('ExecutableSigner');

    time.sleep(1)

    with open(sign_cert_passwd_file_name, 'r') as sign_cert_passwd_file:
        sign_cert_passwd = sign_cert_passwd_file.read().replace('\n', '')
        subprocess.call(                                                    \
            ['signtool.exe', 'sign', '/t',                                  \
             'http://timestamp.digicert.com', '/f', sign_cert_file_name,    \
             '/fd', 'sha256', '/p', sign_cert_passwd, target_file_name])
