#!/usr/bin/python
import sys, getopt, time, switch_auth, switch_parser, re, subprocess

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
        print("Eg : ./switch_basic.py -H abc.com -u user -p XXXXX -m [password_management/all] -f switch_basic.json")
        sys.exit(STATUS_UNKNOWN)

def get_show_run_view_full(ip,username,password,verbose,module_name,filename):
    failed = []
    success = ['aaa is set', 'aaa authenticaion is set properly', 'authentication for console is set', 'line vty authentication is set to radius', 'Default credential is set', 'ssh is enable on live vty', 'Management access is applied on line vty', 'Banner for exec , login is set', 'Secret password is set', 'Password encryption is set', 'snmp server with readonly access is set', 'snmp server with readwrite is not set', 'ACL for SNMP server is set', 'snmp host is set', 'snmp trap is set', 'Hostname is set', 'domain name is set', 'ssh version 2 is set and authentication timeout and retries are set', 'cdp is not set', 'dhcp is not set', 'tcp keepalives are set', 'service pad is not set', 'Logging is enable', 'Logging buffer size is set', 'Logging console is set', 'Logging host is set', 'Timestamps for debug is set', 'Logging source interface is set', 'Ntp server is set', 'Radius server source interface is set', 'ntp source interface is set', 'source ip datagram routing is not set','Compliance rules from the iput file met']

    command1 = {"sh run view full":""}
    result1_status,result1_output,result1_commands_failed = switch_auth.login(ip,username,password,command1.keys(),verbose)

    # Checking if status True?
    if not result1_status:
        print result1_output
        sys.exit(STATUS_CRITICAL)

    # If status False, printing the error
    if result1_commands_failed:
        print "Error: %s"% result1_commands_failed
        sys.exit(STATUS_UNKNOWN)

    # If the result is there, then processing the result.
    sh_run_result =result1_output.values()[0]
    processed_response1 =  sh_run_result[sh_run_result.find('\n')+1:sh_run_result.rfind('\n')]

    #Getting the commands and expected output to pass to authentication module.
    commands_expectedop = switch_parser.get_commands_from_module(module_name,filename,verbose)

    # Getting the error messages for the commands
    command_errors = switch_parser.get_error_message_from_module(module_name,filename,verbose)

    #print(repr(sh_run_result))
    for key,value in commands_expectedop.items():
        if not re.search(value,sh_run_result,re.M):
            failed.append(command_errors[key])

    # For stack switch
    if re.search("switch 2 provision .*",sh_run_result,re.M):
        if re.search("stack-mac persistent timer 0",sh_run_result,re.M):
            stack_message = "Persistent timer is set"
            success.append(stack_message)
        else:
            stack_message = "Persistent timer is not set"
            failed.append(stack_message)
    else:
        stack_message= "Not a stack switch"
        success.append(stack_message)

    if failed:
        return False,failed
    else:
        return True,success

def switch_ospf(ip,username,password,verbose):
    command1 = {"sh ip ospf neighbor":'^$'}

    interfaces_not_configured = set()
    ospf_message = ""

    # Getting the response of the first command
    result1_status, result1_output, result1_commands_failed = switch_auth.login(ip,username,password,command1.keys(),verbose)

    # Checking if status True?
    if not result1_status:
        print result1_output
        sys.exit(STATUS_CRITICAL)

    # If status False, printing the error
    if result1_commands_failed:
        print "Error: %s"% result1_commands_failed
        sys.exit(STATUS_UNKNOWN)

    # If the result is there, then processing the result.
    value1 =result1_output.values()[0]

    processed_response1 =  value1[value1.find('\n')+1:value1.rfind('\n')]
    if re.match(command1.values()[0],processed_response1,re.M):
        ospf_status = True
        if verbose == "True":
            print "Command output and expected output Matched"
        ospf_message = "OSPF not enabled"
        return ospf_status,ospf_message,interfaces_not_configured
    else:
        # Getting the interface list from the first command output.
        interface_list = subprocess.check_output(["""echo "%s"|awk '{{print $6}}'|sed '/^$\|Time/d'"""%processed_response1], shell=True)
        interface_list = interface_list.split('\n')
        interface_list = filter(None,interface_list)
        interface_list = [i.strip() for i in interface_list]

        for interface in interface_list:
            # Checking authentication is set or not
            command2 = {"show running-config view full | s {0}".format(interface): " ip ospf authentication message-digest\r\n ip ospf message-digest-key 1 md5 7 .*\r"}
            result2_status,result2_output,result2_commands_failed = switch_auth.login(ip,username,password,command2.keys(),verbose)

            # Checking if status True?
            if not result2_status:
                print result2_output
                sys.exit(STATUS_CRITICAL)

            # If status False, printing the error
            if result2_commands_failed:
                print "Error: %s"% result2_commands_failed
                sys.exit(STATUS_UNKNOWN)

            value2 = result2_output.values()[0]

            processed_response2 =  value2[value2.find('\n')+1:value2.rfind('\n')]
            if not re.search(command2.values()[0],processed_response2,re.M):
                if verbose == "True":
                    print("Authenitcation is not enabled or md5 is not set for the interface: {0}.".format(interface))
                interfaces_not_configured.add(interface)
        if interfaces_not_configured:
           ospf_message = "Authenitcation is not enabled or md5 is not set for the interfaces: {0}.".format(interfaces_not_configured)
           ospf_status = False
        else:
           ospf_message = "OSPF is configured correctly"
           ospf_status= True

    return ospf_status,ospf_message,interfaces_not_configured

def check_ssh_enable(ip,username,password,verbose):
    command1 = {"sh ip ssh | inc version|retries|timeout":"SSH Enabled - version 2.0\r\nAuthentication timeout: 120 secs; Authentication retries: 3"}

    # Getting the response of the first command
    result1_status,result1_output,result1_commands_failed = switch_auth.login(ip,username,password,command1.keys(),verbose)

    # Checking if status True?
    if not result1_status:
        print result1_output
        sys.exit(STATUS_CRITICAL)

    # If status False, printing the error
    if result1_commands_failed:
        print "Error: %s"% result1_commands_failed
        sys.exit(STATUS_UNKNOWN)

    # If the result is there, then processing the result.
    value1 =result1_output.values()[0]

    processed_response1 =  value1[value1.find('\n')+1:value1.rfind('\n')]
    if not re.match(command1.values()[0],processed_response1,re.M):
        ssh_message = "SSH version 2 is not set and authentication timeout and retries is not set or mismatch."
        ssh_status = False
    else:
        ssh_message = "SSH Enabled"
        ssh_status = True
  
    return ssh_status,ssh_message
 
def check_access_lists(ip,username,password,verbose):
    acces_list_cmd = {"sh access-lists | b  mgmt_access":"Extended IP access list mgmt_access\r\n([ ]+[1-9]0 permit tcp 10.* 0.0.3.255 any eq 22\r\n?){3}([ ]+[1-9]0 permit tcp host 10.* any eq 22\r\n?){6}"}

    acces_list_cmd_status,acces_list_cmd_output,acces_list_cmd_failed =  switch_auth.login(ip,username,password,acces_list_cmd.keys(),verbose)
    # Checking if status True?
    if not acces_list_cmd_status:
        print acces_list_cmd_output
        sys.exit(STATUS_CRITICAL)

    # If status False, printing the error
    if acces_list_cmd_failed:
        print "Error: %s"% acces_list_cmd_failed
        sys.exit(STATUS_UNKNOWN)

    # If the result is there, then processing the result.
    value1 = acces_list_cmd_output.values()[0]

    processed_response1 =  value1[value1.find('\n')+1:value1.rfind('\n')]
    if not re.match(acces_list_cmd.values()[0],processed_response1,re.M):
        acl_message = "ACL for Management access is not set or mismatch"
        acl_status  = False
    else:
        acl_message = "ACL for Management access is set correctly"
        acl_status  = True

    return acl_status,acl_message

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

  get_show_run_view_full_status, get_show_run_view_full_output = get_show_run_view_full(ip,username,password,verbose,module_name,filename)
  get_show_run_view_full_output = ', '.join(map(str, get_show_run_view_full_output)) 
  ospf_status,ospf_message,interfaces_not_configured = switch_ospf(ip,username,password,verbose)
  ssh_status,ssh_message = check_ssh_enable(ip,username,password,verbose)
  acl_status,acl_message = check_access_lists(ip,username,password,verbose)

  show_run_view_full = {get_show_run_view_full_status:get_show_run_view_full_output}
  ospf = {ospf_status:ospf_message}
  ssh = {ssh_status:ssh_message}
  acl = {acl_status:acl_message}

  #icinga output
  if get_show_run_view_full_status and ospf_status and ssh_status and acl_status:
      print("OK! {0}, {1}, {2}, {3}.".format(get_show_run_view_full_output,ospf_message,ssh_message,acl_message))
  else:
      #print("Critical! {0}, {1}, {2}, {3}".format(get_show_run_view_full_output,ospf_message,ssh_message,acl_message))
      final_error = "Critical! "
      for (s1,m1),(s2,m2),(s3,m3),(s4,m4) in zip(show_run_view_full.items(),ospf.items(),ssh.items(),acl.items()):
        if not s1:
          final_error = final_error + m1
        if not s2:
          final_error = final_error + m2
        if not s3:
          final_error = final_error + m3
        if not s4:
          final_error = final_error + m4
     
      final_error = final_error + "."
      print(final_error)
      sys.exit(STATUS_CRITICAL)

if __name__ == "__main__":
   main(sys.argv[1:])
