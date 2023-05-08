import os, json, yaml
import argparse
from networkPolicies import NetworkPolicies
from repository import Repository
from utils import data
from datetime import datetime
from logger import Logger

logger = Logger().logger

BACKUP_DIR = "backups_tmp/"

def do_import(comment='', commit=None, target=None):


  if commit:
    repo = Repository()
    repo.git_revert(commit)
  
  ise = NetworkPolicies()
  ise.export_policy('taking backup for Import task', target)

  ise.create_policy_set(all_policy_sets=True, endingTag='_tmp', target=target)

  bck_policy_sets = ise.read_backup_tmp_policy_set(target=target)
  policies = bck_policy_sets['response']

  #delete old policy sets
  for data in policies:
    if data['name'] != 'Default':
      print("\n## Deleting policy_name: {}".format(data['name']))
      ise.del_policy_set(data['id'])
      print("## policy_name {} deleted".format(data['name']))

  #change policy sets name
  policies_result = ise.get_all_policy_set().response
  policies = policies_result['response']

  for data in policies:
    if data['name'] != 'Default':
      ise.update_policy_set(data)


def do_export(comment, target=None):


  ise = NetworkPolicies()
  ise.export_policy(comment, target)

  repo = Repository()
  repo.save_to_repo(comment, target)

def do_precheck():
  #several functions to validate that policy can be successfully imported

  print("\n### Performing pre-checks to validate that policy can be successfully imported to target device")
  ise = NetworkPolicies()
  pre_check = True
  try: 
    if ise.get_all_policy_set().status_code == 200:
      print("\n### Get all Policy Sets: OK")
    else:
      print("\n### Get all Policy Sets: Fail!!!")
      pre_check = False
  except Exception as e:
    print("### Get all Policy Sets: Fail!!!")
    print("### Exception: {}".format(e))
    pre_check = False
    
  try:
    if ise.get_all_conditions().status_code == 200:
      print("\n### Get all Conditions: OK")
    else:
      print("\n### Get all Conditions: Fail!!!")
      pre_check = False
  except Exception as e:
    print("\n### Get all Conditions: Fail!!!")
    print("### Exception: {}".format(e))
    pre_check = False

  if pre_check:
    print("\n### All pre-check validations were successfully validated\n")
    return True
  else:
    print("\n### Pre-check validations failed\n")
    return False



def main():

    parser = argparse.ArgumentParser()

    # Adding optional argument
    parser.add_argument("-e", "--export", action="store_true")
    parser.add_argument("-i", "--import", action="store_true")
    parser.add_argument("--comment", help = "Include comments about changes", default=None)
    parser.add_argument("--rollback", help = "Include previos comit_id to rollback", default=None)
    parser.add_argument("--target", help = "Include target device", default=None)
    parser.add_argument("--precheck", action="store_true", help = "Command to validate that policy can be successfully imported")
    
    # Read arguments from command line and convert to a python dict
    args = vars(parser.parse_args())
    if args['precheck']:
      do_precheck()

    elif args['export']:
      if not args['comment'] or not args['target']:
        message = "Include comments about changes\n"
        message += 'usage: python ise_policy_mgr.py --export --target <hostname/ip> --comment "Comments about changes"\n'
      
        print(parser.exit(1, message=message))

      else:
        print("performing export policy sets")
        #usage: python ise_policy_mgr.py --export --target <hostname/ip> --comment "some comments"
        start = datetime.now()
        do_export(args['comment'], args['target'])
        finish = datetime.now()
        duration = finish - start
        print('\n\n### Total Duration Task: {} sec.\n'.format(duration.seconds))

    elif args['import'] and args['target']:

      if args['rollback']:
        #usage: python ise_policy_mgr.py --import --target <hostname/ip> --rollback <commit_id>
        print("performing import with rollback")
        #print(args['rollback'])

        start = datetime.now()
        do_import(commit, target=args['rollback'])
        finish = datetime.now()
        duration = finish - start
        print('\n\n### Total Duration Task: {} sec.\n'.format(duration.seconds))

      else:
        print("performing import from previous version")
        #usage: python ise_policy_mgr.py --import --target <hostname/ip>

        start = datetime.now()
        do_import(target=args['target'])
        finish = datetime.now()
        duration = finish - start
        print('\n\n### Total Duration Task: {} sec.\n'.format(duration.seconds))


    else:
      message = 'usage: python ise_policy_mgr.py [--export] [--import] [--target <hostname/IP>][--comment "Comments about changes"] [--rollback "commit_id"]\n'
      print(parser.exit(1, message=message))


    

if __name__ == "__main__":
  main()
