#!/usr/bin/python
import sys, getopt, time, switch_auth, switch_parser,re, subprocess

# Icinga statuses
STATUS_OK = 0
STATUS_WARNING = 1
STATUS_CRITICAL = 2
STATUS_UNKNOWN = 3

# Help details
def usage():
        print("checks the commands for the specified module are configured properly in cisco Cisco switchs")
        print("Usage: ./switch_basic.py -H <IP Adress> -u username -p password -m module_name -f conf_file_path")
        print("-h : Shows this help")
        print("-H : Cisco switch's Hostname")
        print("-u : Cisco switch's Username")
        print("-p : Cisco switch's Password")
        print("-m : The name of the module whose commands to be executed as defined in switch_basic.json. To check all modules, pass 'all' as module name")
        print("-f : switch_basic.json file path")
        print("-v : Enable Verbose")
        print("Eg : ./switch_basic.py -H abc.com -u username -p XXXXX -m [password_management/all] -f switch_basic.json")
        sys.exit(STATUS_UNKNOWN)

def main(argv):
  verbose = "False"
  # Getting commandline arguments
  try:
        opts, args = getopt.getopt(argv,"hH:u:p:m:f:v")
  except getopt.GetoptError:
	usage()
  for opt, arg in opts:
        if opt == '-h':
		usage()
        elif opt in ("-H", "--hostname"):
                ip = arg
        elif opt in ("-u", "--username"):
                username = arg
        elif opt in ("-p", "--password"):
                password = arg
        elif opt in ("-m", "--module_name"):
                module_name = arg
        elif opt in ("-f", "--filename"):
                filename = arg
        elif opt in ("-v", "--verbose"):
                verbose = "True"

  #Getting the commands and expected output to pass to authentication module.
  commands = switch_parser.get_commands_from_module(module_name,filename,verbose)
  
  #Getting the commands and output from the asa firewall from authenticationb module.
  result = switch_auth.login(ip,username,password,commands.keys(),verbose)
  if not result[0]:
    print result[1]
    sys.exit(STATUS_CRITICAL)
  
  if verbose == "True":
    print result[2]
  # Getting the error messages for the commands
  command_errors = switch_parser.get_error_message_from_module(module_name,filename,verbose)

  # Getting the number of lines in the expected output
  output_lines = switch_parser.get_num_of_lines_of_module(module_name,filename,verbose)

  final = switch_parser.compare(result[1],commands,command_errors,output_lines,result[2],verbose)

# ICINGA status
  if final[0]:
    print "OK! Private community string is removed, Public community string is removed, Logging trap is set to information."
    sys.exit(STATUS_OK)
  else:
      print "Critical! {0}.".format(final[1])
      sys.exit(STATUS_CRITICAL)

if __name__ == "__main__":
   main(sys.argv[1:])
