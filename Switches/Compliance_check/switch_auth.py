#!/usr/bin/python
import sys, getopt, paramiko, time, re

def disable_paging(remote_conn,verbose):
  '''Disable paging on a Cisco router. i.e to disable --More-- prompt'''

  remote_conn.send("terminal len 0\n")
  time.sleep(.5)
  # Clear the buffer on the screen
  if verbose == "True":
    print("remote_conn.recv_ready is {0}".format(remote_conn.recv_ready()))
  if remote_conn.recv_ready():
    output = remote_conn.recv(7000)
  return output

def login(hostname,username,password,commands,verbose="False"):
  '''Accepts hostname,username,password and the commands to be executed. 
  Returns the command outputs, commands failed and the status. If it it fails to 
  login to the router, it returns status false and an error message'''

  status = True
  error = "ERROR: Command authorization failed"
  command_output = {}
  commands_failed = {}
  ip=hostname
  username=username
  password=password
  paramiko.util.log_to_file("/dev/null")
  conn_pre = paramiko.SSHClient()
  conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  try:
    conn_pre.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)
    conn = conn_pre.invoke_shell()
    disable_paging(conn,verbose)
    for i in commands:          # Each command runs here
      if conn.recv_ready():
        output = conn.recv(10000)
      if verbose == "True":
        print("executing the command %s" %i)
        print("conn.send_ready:{0}".format(conn.send_ready()))
      conn.send("%s\n" % i)
      time.sleep(10)
      while not conn.recv_ready():
        if verbose == "True":
          print("Not ready")
        time.sleep(2)           # Increase this value if more commands are failing without reason. 
      output = conn.recv(60000)
      if verbose == "True":
        print("output is:\n{0}".format(output))
      if re.search(error,output,re.M):
        if verbose == "True":
          print "Command auth error"
        output = "ERROR: Command authorization failed"
	commands_failed[i] = output
      elif re.search("ERROR:",output,re.M):
        if verbose == "True":
          print "output of the command is:\n%s"%output
        output = "Error while running the command"
      else:
	pass
      command_output[i] = output     # Command output added to a dictionary with command as the key
  except Exception  as e:
    if verbose == "True":
      print e.message
    status = False 
    output = "oops! Something went wrong in authentication!"
    conn_pre.close()
    return status,output,commands_failed
  conn_pre.close()
  return status,command_output,commands_failed
