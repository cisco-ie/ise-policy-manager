import os, json, yaml
import argparse
from networkPolicies import NetworkPolicies
from repository import Repository
from datetime import datetime
from logger import Logger

logger = Logger().logger

BACKUP_DIR = "../backups_tmp/"

def do_import(comment='', commit=None, target=None):


  if commit:
    repo = Repository()
    repo.git_revert(commit)
  
  ise = NetworkPolicies()
  ise.export_policy('taking backup for Import task', target)

  #analize diff policies and apply only changed policy
  bck_policy_sets = ise.read_backup_tmp_policy_set(target=target)
  bck_policy_sets = bck_policy_sets['response']

  #create list with new policies
  new_policies = []
  new = True
  file_policy_sets = ise.read_file_policy_set(target=target)
  for item in file_policy_sets['response']:
    for item_bck in bck_policy_sets:
      if item == item_bck:
        new = False
        
    if new and item['name'] != 'Default':
      logger.info("Policy Name to create: {}".format(item['name']))
      new_policies.append(item) #new policy set not found in current state
    new = True

  #create list to delete policies
  delete = True
  del_policies = []
  for item_bck in bck_policy_sets:
    for item in file_policy_sets['response']:
      if item_bck == item:
        delete = False
    
    if delete and item_bck['name'] != 'Default':
      logger.info("Policy Name to delete: {}".format(item_bck['name']))
      del_policies.append(item_bck) #array to delete
    delete = True

  #delete old policy sets
  logger.info("Checking policies to delete...")
  if del_policies:
    for data in del_policies:
      if data['name'] != 'Default':
        logger.info("## Deleting policy_name: {}".format(data['name']))
        ise.del_policy_set(data['id'])
        logger.info("## policy_name {} deleted".format(data['name']))
  else:
    logger.info("There is no need to delete Policies. All Policies are updated")

  logger.info("Checking new policies...")
  if new_policies:
    for policy in new_policies:
      ise.create_policy_set(name=policy['name'], target=target)
  else:
    logger.info("There is no need to create Policies. All Policies are updated")
  

  if commit:
    comment = 'Rollback to a previous commit'
    repo.save_to_repo(comment, target)


def do_export(comment, target=None, localRepo=None):

  ise = NetworkPolicies()
  ise.backup_all_conditions(target)
  ise.export_policy(comment, target)

  if not localRepo:
    repo = Repository()
    repo.save_to_repo(comment, target)

def do_precheck():
  #several functions to validate that policy can be successfully imported

  #print("\n### Performing pre-checks to validate that policy can be successfully imported to target device")
  logger.info("Performing pre-checks to validate that policy can be successfully imported to target device")
  ise = NetworkPolicies()
  pre_check = True
  try: 
    if ise.get_all_policy_set().status_code == 200:
      logger.info("Get all Policy Sets: OK")
    else:
      logger.error("Get all Policy Sets: Fail!!!")
      pre_check = False
  except Exception as e:
    logger.error("Get all Policy Sets: Fail!!!")
    logger.error("Exception: {}".format(e))
    pre_check = False
    
  try:
    if ise.get_all_conditions().status_code == 200:
      logger.info("### Get all Conditions: OK")
    else:
      logger.info("### Get all Conditions: Fail!!!")
      pre_check = False
  except Exception as e:
    logger.error("### Get all Conditions: Fail!!!")
    logger.error("### Exception: {}".format(e))
    pre_check = False

  if pre_check:
    #print("\n### All pre-check validations were successfully validated\n")
    logger.info("All pre-check validations were successfully validated\n")
    return True
  else:
    #print("\n### Pre-check validations failed\n")
    logger.info("Pre-check validations failed")
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
    parser.add_argument("--localRepo", action="store_true", help = "Use this arg to work with local Repository, not remote Repositoty")
    
    # Read arguments from command line and convert to a python dict
    args = vars(parser.parse_args())
    if args['precheck']:
      do_precheck()

    elif args['export']:
      if not args['comment'] or not args['target']:
        message = "Include comments about changes\n"
        message += 'usage: python ise_policy_mgr.py --export --target <hostname/ip> --comment "Comments about changes"\n'
      
        logger.error(message)
        exit(1)
        #print(parser.exit(1, message=message))

      else:
        logger.info("performing export policy sets")
        #print("performing export policy sets")
        #usage: python ise_policy_mgr.py --export --target <hostname/ip> --comment "some comments"
        start = datetime.now()
        do_export(args['comment'], args['target'], args['localRepo'])
        finish = datetime.now()
        duration = finish - start
        logger.info('### Total Duration Task: {} sec.\n'.format(duration.seconds))
        #print('\n\n### Total Duration Task: {} sec.\n'.format(duration.seconds))

    elif args['import'] and args['target']:

      if args['rollback']:
        #usage: python ise_policy_mgr.py --import --target <hostname/ip> --rollback <commit_id>
        #print("performing import with rollback")
        logger.info("performing import with rollback")
        #print(args['rollback'])

        start = datetime.now()
        do_import(commit=args['rollback'], target=args['target'])
        finish = datetime.now()
        duration = finish - start
        logger.info('### Total Duration Task: {} sec.\n'.format(duration.seconds))
        #print('\n\n### Total Duration Task: {} sec.\n'.format(duration.seconds))

      else:
        #print("performing import from previous version")
        logger.info("performing import from previous version")
        #usage: python ise_policy_mgr.py --import --target <hostname/ip>

        start = datetime.now()
        do_import(target=args['target'])
        finish = datetime.now()
        duration = finish - start
        logger.info('### Total Duration Task: {} sec.\n'.format(duration.seconds))
        #print('\n\n### Total Duration Task: {} sec.\n'.format(duration.seconds))


    else:
      message = 'usage: python ise_policy_mgr.py [--export] [--import] [--target <hostname/IP>][--comment "Comments about changes"] [--rollback "commit_id"]\n'
      logger.error(message)
      exit(1)
      #print(parser.exit(1, message=message))


if __name__ == "__main__":
  main()
