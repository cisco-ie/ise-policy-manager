import os, json, yaml, requests
from base64 import b64encode
from decouple import config
from requests.auth import HTTPBasicAuth
import git
from ciscoisesdk import IdentityServicesEngineAPI
from ciscoisesdk.exceptions import ApiError
from logger import Logger

logger = Logger().logger


BACKUP_TMP = "../backups_tmp/"
BACKUP_DIR = "../repository/ise-policy-repository-https/policy_sets/"
#BACKUP_DIR = "/Users/plencina/Docker/python/Project_Cisco_ISE/ise-policy-repository/policy_sets/"

ISE_USERNAME = config('ISE_USERNAME')
ISE_PASSWORD = config('ISE_PASSWORD')
ISE_BASE_URL = config('ISE_BASE_URL')
ISE_VERSION = config('ISE_VERSION')

class NetworkPolicies(object):
  
  def __init__(self):
    self.api = IdentityServicesEngineAPI(username=ISE_USERNAME,
                                password=ISE_PASSWORD,
                                uses_api_gateway=True,
                                base_url=ISE_BASE_URL,
                                version=ISE_VERSION,
                                verify=False,
                                debug=True,
                                uses_csrf_token=False)

    if not os.path.exists(BACKUP_DIR):
      os.mkdir(BACKUP_DIR)


  def read_backup_tmp_policy_set(self, target='policy_sets'):

    with open(os.path.join(BACKUP_TMP, target+"_tmp.yml")) as f:
      all_policy_sets = yaml.safe_load(f)

    return all_policy_sets

  
  def export_policy(self, comment=None, target='policy_sets'):
    print("Performing Export task")
    try:
      policies_result = self.api.network_access_policy_set.get_all().response

      policies_result['version'] = int(self.get_current_version_number()) + 1
      policies_result['version_comments'] = comment

      policies_count = len(policies_result['response'])
      print("Found {} policy sets".format(policies_count))
      for index, item in enumerate(policies_result['response']):
        
        authen_policy = self.get_authentication_policy_by_Id(item['id']).response
        policies_result['response'][index]['authentication_policy'] = authen_policy['response']

        author_policy = self.get_authorization_policy_by_Id(item['id']).response
        policies_result['response'][index]['authorization_policy'] = author_policy['response']

        #author_policy = self.backup_authorization_excepction_policy(item['id'])
        #policies_result['response'][index]['authorization_exception_policy'] = author_policy['response']

        print("Policy Set #{} exported: {}".format(index+1, item['name']))

        #author_policy = self.backup_authorization_global_exception_policy(item['id'])
        #policies_result['response'][index]['authorization_global_exception_policy'] = author_policy['response']

      #json_object = json.dumps(policies_result, indent=4)

      #with open(os.path.join(BACKUP_DIR, "bck_all_policy_set.json"), "w") as outfile:
      #  outfile.write(json_object)

      json_str = json.dumps(policies_result)
      python_dict = json.loads(json_str)
   
      with open(os.path.join(BACKUP_TMP, target+"_tmp.yml"), "w") as f:
        f.write(yaml.safe_dump(python_dict, sort_keys=False))

    except Exception as e:
      print("Export failed!!!: {}".format(e))



  def get_current_version_number(self):

    with open(os.path.join(BACKUP_DIR, "policy_sets.yml")) as f:
      result = yaml.safe_load(f)

    return result['version']


  def get_all_policy_set(self):
    dictionary_result = self.api.network_access_policy_set.get_all()
    return dictionary_result


  def get_authentication_policy_by_Id(self, policyId):
    dictionary_result = self.api.network_access_authentication_rules.get_all(policyId)
    #print('\n## Get Authentication Policy ##')
    #print(json.dumps(dictionary_result, indent=4))
    return dictionary_result

  def get_authorization_policy_by_Id(self, policyId):
    dictionary_result = self.api.network_access_authorization_rules.get_all(policyId)
    #print('\n## Get Authorization Policy ##')
    #print(json.dumps(dictionary_result, indent=4))
    return dictionary_result

  def backup_authorization_excepction_policy(self, policyId):
    dictionary_result = self.api.network_access_authorization_exception_rules.get_all(policyId).response
    #print(dictionary_result)
    return dictionary_result

  def backup_authorization_global_exception_policy(self, policyId):
    dictionary_result = self.api.network_access_authorization_global_exception_rules.get_all(policyId).response
    #print(dictionary_result)
    return dictionary_result

  def backup_allowed_protocols(self):
    response = []
    dictionary_result = self.api.allowed_protocols.get_all().response
    for item in dictionary_result['SearchResult']['resources']:
      response.append(self.backup_allowed_protocols_by_Id(item['id']))
    
    json_object = json.dumps(response, indent=4)

    with open(os.path.join(BACKUP_DIR, "bck_allowed_protocols.json"), "w") as outfile:
      outfile.write(json_object)

    return dictionary_result

  def backup_allowed_protocols_by_Id(self, id):
    dictionary_result = self.api.allowed_protocols.get_allowed_protocol_by_id(id).response
    #print(json.dumps(dictionary_result, indent=4))
    return dictionary_result


  def backup_authorization_profile(self):
    response = []
    dictionary_result = self.api.authorization_profile.get_all().response
    for item in dictionary_result['SearchResult']['resources']:
      response.append(self.backup_authorization_profile_by_Id(item['id']))
    
    json_object = json.dumps(response, indent=4)

    with open(os.path.join(BACKUP_DIR, "bck_authorization_profile.json"), "w") as outfile:
      outfile.write(json_object)

    return dictionary_result

  def backup_authorization_profile_by_Id(self, id):
    dictionary_result = self.api.authorization_profile.get_authorization_profile_by_id(id).response
    #print(json.dumps(dictionary_result, indent=4))
    return dictionary_result

  
  def backup_security_groups(self):
    response = []
    dictionary_result = self.api.security_groups.get_all().response
    for item in dictionary_result['SearchResult']['resources']:
      response.append(self.backup_security_groups_by_Id(item['id']))
    
    json_object = json.dumps(response, indent=4)

    with open(os.path.join(BACKUP_DIR, "bck_security_groups.json"), "w") as outfile:
      outfile.write(json_object)

    return dictionary_result

  def backup_security_groups_by_Id(self, id):
    dictionary_result = self.api.security_groups.get_security_group_by_id(id).response
    #print(json.dumps(dictionary_result, indent=4))
    return dictionary_result
  

  def backup_identity_sequence(self):
    response = []
    dictionary_result = self.api.identity_sequence.get_all().response
    for item in dictionary_result['SearchResult']['resources']:
      response.append(self.backup_identity_sequence_by_Id(item['id']))
    
    json_object = json.dumps(response, indent=4)

    with open(os.path.join(BACKUP_DIR, "bck_identity_sequence.json"), "w") as outfile:
      outfile.write(json_object)

    return dictionary_result

  def backup_identity_sequence_by_Id(self, id):
    dictionary_result = self.api.identity_sequence.get_identity_sequence_by_id(id).response
    #print(json.dumps(dictionary_result, indent=4))
    return dictionary_result

    
  def backup_identity_stores(self):
    dictionary_result = self.api.network_access_identity_stores.get_all().response
    print(json.dumps(dictionary_result, indent=4))
    return dictionary_result


    
  def backup_dictionary(self):
    dictionary_result = self.api.network_access_dictionary.get_all().response
    #print(dictionary_result)
    json_object = json.dumps(dictionary_result, indent=4)
  
    with open(os.path.join(BACKUP_DIR, "bck_all_dictionary.json"), "w") as outfile:
      outfile.write(json_object)

    json_str = json.dumps(dictionary_result)
    python_dict = json.loads(json_str)

    with open(os.path.join(BACKUP_DIR, "bck_all_dictionary.yaml"), "w") as f:
      f.write(yaml.dump(python_dict))


  def backup_dictionary_attributes(self):
    response = []
    dictionary_result = self.api.network_access_dictionary_attributes_list.get_all_policy_set().response
    
    json_object = json.dumps(dictionary_result.response, indent=4)

    with open(os.path.join(BACKUP_DIR, "bck_dictionary_attributes.json"), "w") as outfile:
      outfile.write(json_object)

    return dictionary_result

  def get_network_conditions_by_name(self, name):
    try:
      dictionary_result = self.api.network_access_conditions.get_network_access_condition_by_name(name).response
      #print(json.dumps(dictionary_result, indent=4))
      return dictionary_result.response.id
    except Exception as e:
      return
   
  def get_all_conditions(self):
    dictionary_result = self.api.network_access_conditions.get_all()
    return dictionary_result
    

  def backup_all_conditions(self):
    dictionary_result = self.api.network_access_conditions.get_all().response
    #print(dictionary_result)
    json_object = json.dumps(dictionary_result, indent=4)

    with open(os.path.join(BACKUP_DIR, "bck_all_conditions.json"), "w") as outfile:
      outfile.write(json_object)


  def del_policy_set(self, policyId):
    dictionary_result = self.api.network_access_policy_set.delete_network_access_policy_set_by_id(policyId).response
    #print(json.dumps(dictionary_result, indent=4))
    return dictionary_result

  
  def read_file_policy_set(self, target='policy_sets'):

    with open(os.path.join(BACKUP_DIR, target+".yml")) as f:
      all_policy_sets = yaml.safe_load(f)

    return all_policy_sets


  def create_policy_set(self, name=None, all_policy_sets=False, endingTag='', target=None):

    file_policy_sets = self.read_file_policy_set(target)
    policies = []

    if all_policy_sets:
      policies = file_policy_sets['response']
    else:
      for item in file_policy_sets['response']:
        if item['name'] == name:
          policies.append(item)
          break

    #print("Print all policy sets from policy_sets.yml")
    #print(policies)

    for data in policies:

      if data['name'] != 'Default':
    
        values = {
          'description': '' if data.get('description') == None else data.get('description'),
          'default': data.get('default'),
          'is_proxy': data.get('isProxy', False),
          'name': data.get('name')+endingTag,
          'rank': data.get('rank'),
          'service_name': data.get('serviceName'),
          'state': data.get('state')
          
        }

        print("\n### Working on Policy Set : {} ###".format(values['name']))

        condition = data.get('condition')
        #print(condition)
        condition.pop('link')
        if condition.get('dictionaryValue', False) == None:
          condition.pop('dictionaryValue')
          

        if condition.get('conditionType', False) == 'ConditionReference':
          if condition.get('description', False) == None:
            condition.pop('description')

        if condition.get('conditionType', False) == 'ConditionAndBlock' or condition.get('conditionType', False) == 'ConditionOrBlock':
          for index, item in enumerate(condition.get('children')):
            condition.get('children')[index].pop('link')

            if item.get('id', False):
              condition.get('children')[index].pop('id')
            if item.get('dictionaryValue', False) == None:
              condition.get('children')[index].pop('dictionaryValue')
            if item.get('conditionType') == 'ConditionReference':
              condition['children'][index]['id'] = self.get_network_conditions_by_name(item.get('name'))
              condition.get('children')[index].pop('name')
              condition.get('children')[index].pop('description')

        
        values['condition'] = condition

        #print('\n### print values for policy set ###')
        #print(json.dumps(values, indent=4))

        authentication_policy = data.get('authentication_policy')
        for index, item in enumerate(authentication_policy):
          authentication_policy[index].get('rule').pop('id')
          authentication_policy[index].pop('link')
        
        #print('\n### print authentication policy backup ###')
        #print(json.dumps(authentication_policy, indent=4))

        authorization_policy = data.get('authorization_policy')
        for index, item in enumerate(authorization_policy):
          authorization_policy[index].get('rule').pop('id')
          authorization_policy[index].pop('link')

        #print('\n### print authorization policy backup ###')
        #print(json.dumps(authorization_policy, indent=4))

        try:
          dictionary_result = self.api.network_access_policy_set.create_network_access_policy_set(**values).response
          policy_id = dictionary_result.response.id
          print("### Policy Set created: {}. policy_id: {} ###\n".format(values['name'], policy_id))

          #authentication rule section
          current_authen_policy = self.get_authentication_policy_by_Id(dictionary_result.response.id).response.get('response')[0]

          for item in authentication_policy:
            if item.get('rule').get('name') != 'Default':
              #create new authentication rules based on the original backup
              item.get('rule').get('condition').pop('dictionaryValue')
              item.get('rule').get('condition').pop('link')
              self.create_authentication_rule(policy_id, item)

          for item in authentication_policy:
            if item.get('rule').get('name') == 'Default':
              #update Default authentication rule
              self.update_authentication_rule(current_authen_policy.get('rule').get('id'), policy_id, item)


          #authorization rule section
          current_author_policy = self.get_authorization_policy_by_Id(dictionary_result.response.id).response.get('response')[0]

          for item in authorization_policy:
            if item.get('rule').get('name') != 'Default':
              #create new authorization rules based on the original backup
              item.get('rule').get('condition').pop('link')
              if item.get('rule').get('condition').get('conditionType') == 'ConditionReference':
                item['rule']['condition']['id'] = self.get_network_conditions_by_name(item.get('rule').get('condition').get('name'))
                item.get('rule').get('condition').pop('name')
              self.create_authorization_rule(policy_id, item)

          for item in authorization_policy:
            if item.get('rule').get('name') == 'Default':
              #update Default authorization rule
              self.update_authorization_rule(current_author_policy.get('rule').get('id'), policy_id, item)
        
          #return dictionary_result.response.id
        except Exception as e:
          print(" --- ERROR ---: {}".format(e))

    
  def update_authentication_rule(self, id, policy_id, data):

    values = data
    values['id'] = id
    values['policy_id'] = policy_id

    #print('\n### values to update authentication rule ###')
    #print(values)

    url = "{}/api/v1/policy/network-access/policy-set/{}/authentication/{}".format(ISE_BASE_URL, policy_id, id)

    encoded_credentials = b64encode(bytes(f'{ISE_USERNAME}:{ISE_PASSWORD}',encoding='ascii')).decode('ascii')

    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic {}'.format(encoded_credentials)
    }

    try:
      response = requests.request("PUT", url, verify=False, headers=headers, data=json.dumps(values))

      print("Authentication rule updated: {}".format(values['rule']['name']))

    except Exception as e:
      print(" --ERROR --: {}".format(e))


  def create_authentication_rule(self, policy_id, data):

    values = data
    values['policy_id'] = policy_id    

    #print('\n### values to create authentication rule ###')
    #print(values)

    url = "{}/api/v1/policy/network-access/policy-set/{}/authentication".format(ISE_BASE_URL, policy_id)
    encoded_credentials = b64encode(bytes(f'{ISE_USERNAME}:{ISE_PASSWORD}',encoding='ascii')).decode('ascii')

    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic {}'.format(encoded_credentials)
    }

    try:
      response = requests.request("POST", url, verify=False, headers=headers, data=json.dumps(values))
      
      print("Authentication rule created: {}".format(values['rule']['name']))

    except Exception as e:
      print(" --ERROR --: {}".format(e))
      
      


  def create_authorization_rule(self, policy_id, data):

    values = data
    values['policy_id'] = policy_id    

    conditionType = values['rule']['condition']['conditionType']

    if conditionType == 'ConditionOrBlock' or conditionType == 'ConditionAndBlock' or conditionType == 'LibraryConditionOrBlock':
      for index, item in enumerate(values['rule']['condition']['children']):
        if item.get('children', False):
          for subindex, subitem in enumerate(item['children']):
            values.get('rule').get('condition').get('children')[index].get('children')[subindex].pop('link')
            values.get('rule').get('condition').get('children')[index].get('children')[subindex].pop('dictionaryValue', None)

        else:
          values.get('rule').get('condition').get('children')[index].pop('link')
          values.get('rule').get('condition').get('children')[index].pop('dictionaryValue', None)

    elif conditionType == 'ConditionAttributes':
      values.get('rule').get('condition').pop('dictionaryValue', None)


    #print('\n### values to create authorization rule ###')
    #print(values)

    url = "{}/api/v1/policy/network-access/policy-set/{}/authorization".format(ISE_BASE_URL, policy_id)
    encoded_credentials = b64encode(bytes(f'{ISE_USERNAME}:{ISE_PASSWORD}',encoding='ascii')).decode('ascii')

    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic {}'.format(encoded_credentials)
    }

    try:
      response = requests.request("POST", url, verify=False, headers=headers, data=json.dumps(values))

      print("Authorization rule created: {}".format(values['rule']['name']))

    except Exception as e:
      print(" --ERROR --: {}".format(e))


  def update_authorization_rule(self, id, policy_id, data):

    values = data
    values['id'] = id
    values['policy_id'] = policy_id

    #print('\n### values to update authorization rule ###')
    #print(values)

    url = "{}/api/v1/policy/network-access/policy-set/{}/authorization/{}".format(ISE_BASE_URL, policy_id, id)

    encoded_credentials = b64encode(bytes(f'{ISE_USERNAME}:{ISE_PASSWORD}',encoding='ascii')).decode('ascii')

    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic {}'.format(encoded_credentials)
    }

    try:
      response = requests.request("PUT", url, verify=False, headers=headers, data=json.dumps(values))

      print("Authorization rule udpated: {}".format(values['rule']['name']))

    except Exception as e:
      print(" --ERROR --: {}".format(e))



  def create_security_group(self, name, value=-1, description=None):

    try:
      dictionary_result = self.api.security_groups.create_security_group(
        name='SGT_Test_Pablo',
        value=-1,
        description=description
      )
      print(dictionary_result.headers.Location)

      return dictionary_result.headers.Location.split('/')[-1]
    except Exception as e:
      print(e)

    
  def create_allowed_protocols(self, data):

    values = {
      'name': data.get('name'),
      'description': data.get('description'),
      'process_host_lookup': data.get('processHostLookup', False),
      'allow_pap_ascii': data.get('allowPapAscii', False),
      'allow_chap': data.get('allowChap', False),
      'allow_ms_chap_v1': data.get('allowMsChapV1', False),
      'allow_ms_chap_v2': data.get('allowMsChapV2', False),
      'allow_eap_md5': data.get('allowEapMd5', False),
      'allow_leap': data.get('allowLeap', False),
      'allow_eap_fast': data.get('allowEapFast', False),
      'allow_eap_tls': data.get('allowEapTls', False),
      'allow_eap_ttls': data.get('allowEapTtls', False),
      'allow_peap': data.get('allowPeap', False),
      'allow_teap': data.get('allowTeap', False),
      'allow_preferred_eap_protocol': data.get('allowPreferredEapProtocol', False),
      'eap_tls_l_bit': data.get('eapTlsLBit', False),
      'allow_weak_ciphers_for_eap': data.get('allowWeakCiphersForEap', False),
      'require_message_auth': data.get('requireMessageAuth', False)
    }

    if values.get('allow_eap_tls'):
      values['eap_tls'] = data.get('eapTls')

    if values.get('allow_peap'):
      values['peap'] = data.get('peap')
    
    if values.get('allow_eap_ttls'):
      values['eap_ttls'] = data.get('eapTtls')

    if values.get('allow_eap_fast'):
      values['eap_fast'] = data.get('eapFast')

    if values.get('allow_teap'):
      values['teap'] = data.get('teap')

    if values.get('allow_preferred_eap_protocol'):
      values['preferred_eap_protocol'] = data.get('preferredEapProtocol')

    print(json.dumps(values, indent=4))

    try:
      dictionary_result = self.api.allowed_protocols.create_allowed_protocol(**values)

      print(dictionary_result.headers.Location)

      return dictionary_result.headers.Location.split('/')[-1]

    except Exception as e:
      print(e)

    
  def update_policy_set(self, data):

    values = {
      'name': data['name'][:-4],
      'serviceName': data['serviceName'],
      'condition': data['condition']
    }
    
    url = "{}/api/v1/policy/network-access/policy-set/{}".format(ISE_BASE_URL, data['id'])

    encoded_credentials = b64encode(bytes(f'{ISE_USERNAME}:{ISE_PASSWORD}',encoding='ascii')).decode('ascii')

    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic {}'.format(encoded_credentials)
    }

    try:
      response = requests.request("PUT", url, verify=False, headers=headers, data=json.dumps(values))

      print("Policy Set udpated: {}".format(values['name']))
      return True

    except Exception as e:
      print(" --ERROR --: {}".format(e))
      return False

