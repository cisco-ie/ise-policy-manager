import os, json, yaml
from networkPolicies import NetworkPolicies
from repository import Repository
from utils import data

BACKUP_DIR = "backups/"

ise = NetworkPolicies()
#ise.clone_repo()
#ise.export_policy()
#ise.backup_allowed_protocols()
#ise.backup_authorization_profile()
#ise.backup_security_groups()
#ise.backup_identity_sequence()
#ise.backup_identity_stores()
#ise.backup_allowed_protocols_by_Id('d1d8a150-17a5-11eb-986d-8ab0296b08e9')
#ise.backup_dictionary()
#ise.backup_authorization_global_exception_policy("5842d6b6-8f03-4ed7-ad68-7d148ea56228")
#ise.backup_authentication_policy('cfc06e97-79f8-40ce-ba7f-211dc56de3d0')
#ise.get_network_conditions_by_name('Wireless_81X')
#ise.get_conditions()

#ise.create_security_group()
#ise.backup_dictionary_attributes()
#ise.backup_dictionary()
#add.create_allowed_protocols(data.allowedProtocols)

#add.create_policy_set(name='LHR14_Switch_Exception', endingTag='_tmp')

values = {
      'id': 'b1874c8a-7dee-40d6-9a9f-b8e685ebb322',
      'name': 'ISE_Loop_vidcast',
      'serviceName': 'AMZN_EAP-TLS',
      'condition': 'ConditionAttributes'
    }
ise.update_policy_set(values)