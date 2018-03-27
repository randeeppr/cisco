#!/usr/bin/python3.4
# Randeep P R, randeep123@gmail.com
import requests, urllib3, time, sys, getopt, os, subprocess, datetime, re, socket
from xml.etree import ElementTree

# Icinga exit status
STATUS_OK=0
STATUS_WARNING=1
STATUS_CRITICAL=2
STATUS_UNKNOWN=3

# Usage
def usage():
        print("Checks the membership of host specifed in Cisco prime.")
        print("Usage: ./check_prime_membership.py -H IP_Adress -u username -p password -V")
        print("\t-h : Shows this help")
        print("\t-H : Hostname")
        print("\t-u : API Username")
        print("\t-p : API Password")
        print("\t-V : Enable Verbose")
        print("Eg : ./check_prime_membership.py -H Hostname -u apiuser -p QAZ2wsx -V")
        sys.exit(STATUS_UNKNOWN)

# Main function starts here
def main(argv):
  verbose = "False"
  # Getting commandline arguments
  try:
        opts, args = getopt.getopt(argv,"hH:u:p:V")
  except getopt.GetoptError:
        usage()
  for opt, arg in opts:
        if opt == '-h':
                usage()
        elif opt in ("-H", "--hostname"):
                hostname = arg
        elif opt in ("-u", "--username"):
                username = arg
        elif opt in ("-p", "--password"):
                password = arg
        elif opt in ("-V", "--Verbose"):
                verbose = "True"

  # Disable warnings
  urllib3.disable_warnings()

  # Check whether file exists or not. If exists, find the age of the file. Else call the API and create the file.
  file_path="/tmp/icinga/hosts_in_cisco_prime.txt"
  if os.path.isfile(file_path):
    file_mod_time = os.stat(file_path).st_mtime
    last_time = (time.time() - file_mod_time) / 60
  else:
    try:
      r = requests.get('https://prime.organization.com/webacs/api/v3/data/Devices?adminStatus=managed&.maxResults=1000&.full=true', auth=('{0}'.format(username), '{0}'.format(password)),verify=False)
      if verbose == "True":
        print("File not found. Creating file")
      f = open(file_path, 'w')
      f.write("{0}".format(r.text))
      f.close()
      last_time = 0
    except Exception as e:
      print("Error! Couldnt get response from api")
      if verbose == "True":
        print(e.message)
      sys.exit(STATUS_UNKNOWN)
  
  if verbose == "True":
    print("Age of the file is {0} minutes.".format(last_time))

  # If the file exists and age of the file is greater than 12 hours, call the api again. 
  if last_time > 720:
    # Getting device details from Cisco prime via API
    try:
      r = requests.get('https://prime.organization.com/webacs/api/v3/data/Devices?adminStatus=managed&.maxResults=1000&.full=true', auth=('{0}'.format(username), '{0}'.format(password)),verify=False)
      if verbose == "True":
        print("File is stale. Updating the file.")
      f = open(file_path, 'w')
      f.write("{0}".format(r.text))
      f.close()
    except Exception as e:
      print("Error! Couldnt get response from api")
      if verbose == "True":
        print(e.message)
      sys.exit(STATUS_UNKNOWN)

  with open(file_path, 'r') as myfile:
    data=myfile.read()

  # Icinga status message
  """This check is for nornal hosts like switches and routers"""
  if re.search(hostname,data,re.IGNORECASE) or re.search(hostname.replace('.organization.com',''),data,re.IGNORECASE):
    print("OK! {0} is present in Cisco Prime.".format(hostname))
    sys.exit(STATUS_OK)
  elif re.search("^asa",hostname,re.IGNORECASE) and (re.search("-a",hostname,re.IGNORECASE) or re.search("-b",hostname,re.IGNORECASE)):
    """This check is for ASA firewalls"""
    if verbose == "True":
      print("This is an ASA host!")
    # Finding the ip address from the hostname to support ASA primary and secondary devices. 
    try:
      ip = socket.gethostbyname(hostname)
    except Exception as e:
      print("Error! Couldnt get the ip address for the given hostname of this ASA Firewall!")
      sys.exit(STATUS_UNKNOWN)
    if re.search(ip,data):
      print("OK! {0} is present in Cisco Prime.".format(hostname))
      sys.exit(STATUS_OK)
    else:
      print("Critical! Couldn't find {0} in Cisco Prime.".format(hostname))
      sys.exit(STATUS_CRITICAL)

  else:
    print("Critical! Couldn't find {0} in Cisco Prime.".format(hostname))
    sys.exit(STATUS_CRITICAL)

if __name__ == "__main__":
   main(sys.argv[1:])
