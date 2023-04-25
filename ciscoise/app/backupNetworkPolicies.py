import os, json, yaml
from dotenv import load_dotenv
import git
from ciscoisesdk import IdentityServicesEngineAPI
from ciscoisesdk.exceptions import ApiError

BACKUP_TMP = "backups_tmp/"
BACKUP_DIR = "repository/ise-policy-repository-https/policy_sets/"
#BACKUP_DIR = "/Users/plencina/Docker/python/Project_Cisco_ISE/ise-policy-repository/policy_sets/"


class BackupNetworkPolicies(object):
  
  def __init__(self):
    load_dotenv()
    self.api = IdentityServicesEngineAPI(username=os.environ['ISE_USERNAME'],
                                password=os.environ['ISE_PASSWORD'],
                                uses_api_gateway=True,
                                base_url=os.environ['ISE_BASE_URL'],
                                version=os.environ['ISE_VERSION'],
                                verify=False,
                                debug=True,
                                uses_csrf_token=False)

    if not os.path.exists(BACKUP_DIR):
      os.mkdir(BACKUP_DIR)


  def read_backup_tmp_policy_set(self):

    with open(os.path.join(BACKUP_TMP, "policy_sets_tmp.yml")) as f:
      all_policy_sets = yaml.safe_load(f)

    return all_policy_sets

  
  def export_policy(self, comment=None):
    print("Performing Export task")
    try:
      policies_result = self.api.network_access_policy_set.get_all().response

      policies_result['version'] = int(self.get_current_version_number()) + 1
      policies_result['version_comments'] = comment

      policies_count = len(policies_result['response'])
      print("Found {} policy sets".format(policies_count))
      for index, item in enumerate(policies_result['response']):
        
        authen_policy = self.backup_authentication_policy(item['id'])
        policies_result['response'][index]['authentication_policy'] = authen_policy['response']

        author_policy = self.backup_authorization_policy(item['id'])
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
      with open(os.path.join(BACKUP_TMP, "policy_sets_tmp.yml"), "w") as f:
        f.write(yaml.safe_dump(python_dict, sort_keys=False))

    except Exception as e:
      print("Export failed!!!: {}".format(e))



  def get_current_version_number(self):

    with open(os.path.join(BACKUP_DIR, "policy_sets.yml")) as f:
      result = yaml.safe_load(f)

    return result['version']


  def get_all_policy_set(self):
    dictionary_result = self.api.network_access_policy_set.get_all().response
    return dictionary_result


  def backup_authentication_policy(self, policyId):
    dictionary_result = self.api.network_access_authentication_rules.get_all(policyId).response
    #print('\n## Get Authentication Policy ##')
    #print(json.dumps(dictionary_result, indent=4))
    return dictionary_result

  def backup_authorization_policy(self, policyId):
    dictionary_result = self.api.network_access_authorization_rules.get_all(policyId).response
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
    
    json_object = json.dumps(dictionary_result, indent=4)

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
   

  def get_conditions(self):
    dictionary_result = self.api.network_access_conditions.get_all().response
    #print(dictionary_result)
    json_object = json.dumps(dictionary_result, indent=4)

    with open(os.path.join(BACKUP_DIR, "bck_all_conditions.json"), "w") as outfile:
      outfile.write(json_object)


  def del_policy_set(self, policyId):
    dictionary_result = self.api.network_access_policy_set.delete_network_access_policy_set_by_id(policyId).response
    #print(json.dumps(dictionary_result, indent=4))
    return dictionary_result
