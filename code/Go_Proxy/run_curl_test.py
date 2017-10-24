import os
import shlex
from subprocess import check_output

f = open("file_list.txt", 'r')
file_list = []
for line in f:
    file_list.append(line.strip())
f.close()

for file_name in file_list:
    DEVNULL = open(os.devnull, 'wb', 0)
    curl_cmd = "curl -w %{http_code} -o /dev/null http://98.158.184.88/" + file_name + " -x 127.0.0.1:12345"
    http_code = int(check_output(shlex.split(curl_cmd), stderr=DEVNULL))
    if http_code != 200:
        print(file_name + " " + str(http_code))
