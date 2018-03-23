#!/usr/bin/python
import re,json
# command_outputis the dictionary contains command and output from the ASA Firewall( Send from the switch_auth module via check)
# commands_expected the dictionary contains command and expected output from the file variables.json.

def compare(command_outputs,commands_expected,commands_errors,output_lines,commands_failed={},verbose="False"):
  ''''Compare function is the most important function in the asa checks. It accept command_outputs which is the output from routers,
  command_expected, which is taken from variables.json file and compares them. If a expected output and actual output differs, then
  it shows the corresponding error from command_errors(which is again taken from variables.json) for the failed command. If the result
  mismatches, it also checks whether the command execution was failed(permission issues) from the dictionary commands_failed.'''

  status = True
  # Declaring the lists for colloecting failed and succeeded commands
  failed=[]
  success=[]
  
  for key, value in command_outputs.items():
    #print key, value
    processed_response =  value[value.find('\n')+1:value.rfind('\n')]
    if verbose == "True":
      print "command : %s"%key
      print "Resp :%s"%repr(processed_response)
      print "Exp :%s"%repr(commands_expected[key])
    if re.match(commands_expected[key],processed_response,re.M):
      if verbose == "True":
        print "Command output and expected output Matched"
      output=processed_response
      length = len(output.split('\n'))
      expected_len=int(output_lines[key])
      if expected_len <= length:
        if verbose == "True":
          print "Number of lines in the command output matched\n"
        success.append(key)
      else:
        if verbose == "True":
          print "Number of lines in the output {0} and expected {1} not matched\n".format(length,expected_len)
        status = False
        failed.append(commands_errors[key])
    else:
      status = False
      if verbose == "True":
        print "Command output and expected output not Matched\n"
      failed.append(commands_errors[key])

  if failed:  
    return status,failed,commands_failed
  else:
    return status,success

def get_commands_from_module(module,filename,verbose="False"):
  '''This function is used for obtaining commands for the module specified. 
  Details will be taken from variables.json file.'''

  commands={}
  json_file = open(filename)
  json_str = json_file.read()
  json_data = json.loads(json_str)
  if module == "all":
    for i in json_data.keys():
      for j in json_data[i]:
        key = j.encode("utf-8")
        #print i, key
        value = json_data[i][j][u'expected_output'].encode("utf-8")
        commands[key]=value
    return commands
  else:
    for i in json_data[module]:
      key = i.encode("utf-8")
      value = json_data[module][key][u'expected_output'].encode("utf-8")
      commands[key]=value
      #print commands
    return commands  

def get_error_message_from_module(module,filename,verbose="False"):
  '''This function is used for obtaining error messages for the module specified. 
  Details will be taken from variables.json file.'''
  commands_errors={}
  json_file = open(filename)
  json_str = json_file.read()
  json_data = json.loads(json_str)
  if module == "all":
    for i in json_data.keys():
      for j in json_data[i]:
        key = j.encode("utf-8")
        #print i, key
        value = json_data[i][j][u'error_message'].encode("utf-8")
        commands_errors[key]=value
    return commands_errors
  else:
    for i in json_data[module]:
      key = i.encode("utf-8")
      value = json_data[module][key][u'error_message'].encode("utf-8")
      commands_errors[key]=value
      #print commands
    return commands_errors

def get_num_of_lines_of_module(module,filename,verbose="False"):
  '''This function is used for obtaining the number of lines in the expected output
  for the module specified. Details will be taken from variables.json file.'''

  output_lines={}
  json_file = open(filename)
  json_str = json_file.read()
  json_data = json.loads(json_str)
  if module == "all":
    for i in json_data.keys():
      for j in json_data[i]:
        key = j.encode("utf-8")
        #print i, key
        value = json_data[i][j][u'num_of_lines'].encode("utf-8")
        #print "value is %s"% value
        output_lines[key]=value
    return output_lines
  else:
    for i in json_data[module]:
      key = i.encode("utf-8")
      value = json_data[module][key][u'num_of_lines'].encode("utf-8")
      #print "value is %s"% value
      output_lines[key]=value
    return output_lines
