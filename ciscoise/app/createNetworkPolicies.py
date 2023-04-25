import os, json, requests
import yaml
from ciscoisesdk import IdentityServicesEngineAPI
from ciscoisesdk.exceptions import ApiError
from backupNetworkPolicies import BackupNetworkPolicies

BACKUP_TMP = "backups_tmp/"
BACKUP_DIR = "repository/ise-policy-repository-https/policy_sets/"

class CreateNetworkPolicies(object):
  
  def __init__(self):
    self.api = IdentityServicesEngineAPI(username='admin',
                                password='Bundle123$',
                                uses_api_gateway=True,
                                base_url='https://10.86.191.239',
                                version='3.1_Patch_1',
                                verify=False,
                                debug=True,
                                uses_csrf_token=False)

    if not os.path.exists(BACKUP_DIR):
      os.mkdir(BACKUP_DIR)


  def read_file_policy_set(self):

    with open(os.path.join(BACKUP_DIR, "policy_sets.yml")) as f:
      all_policy_sets = yaml.safe_load(f)

    return all_policy_sets


  def create_policy_set(self, name=None, all_policy_sets=False, endingTag=''):

    file_policy_sets = self.read_file_policy_set()
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
        ise = BackupNetworkPolicies()
    
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
              condition['children'][index]['id'] = ise.get_network_conditions_by_name(item.get('name'))
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
          current_authen_policy = ise.backup_authentication_policy(dictionary_result.response.id).get('response')[0]

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
          current_author_policy = ise.backup_authorization_policy(dictionary_result.response.id).get('response')[0]

          for item in authorization_policy:
            if item.get('rule').get('name') != 'Default':
              #create new authorization rules based on the original backup
              item.get('rule').get('condition').pop('link')
              if item.get('rule').get('condition').get('conditionType') == 'ConditionReference':
                item['rule']['condition']['id'] = ise.get_network_conditions_by_name(item.get('rule').get('condition').get('name'))
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

    url = "https://10.86.191.239/api/v1/policy/network-access/policy-set/{}/authentication/{}".format(policy_id, id)

    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic YWRtaW46QnVuZGxlMTIzJA=='
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

    url = "https://10.86.191.239/api/v1/policy/network-access/policy-set/{}/authentication".format(policy_id)
    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic YWRtaW46QnVuZGxlMTIzJA=='
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

    url = "https://10.86.191.239/api/v1/policy/network-access/policy-set/{}/authorization".format(policy_id)
    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic YWRtaW46QnVuZGxlMTIzJA=='
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

    url = "https://10.86.191.239/api/v1/policy/network-access/policy-set/{}/authorization/{}".format(policy_id, id)

    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic YWRtaW46QnVuZGxlMTIzJA=='
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
    
    url = "https://10.86.191.239/api/v1/policy/network-access/policy-set/{}".format(data['id'])

    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic YWRtaW46QnVuZGxlMTIzJA=='
    }

    try:
      response = requests.request("PUT", url, verify=False, headers=headers, data=json.dumps(values))

      print("Policy Set udpated: {}".format(values['name']))
      return True

    except Exception as e:
      print(" --ERROR --: {}".format(e))
      return False

