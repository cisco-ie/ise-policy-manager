import os, json, yaml
import argparse
from networkPolicies import NetworkPolicies
from repository import Repository
from utils import data
from datetime import datetime

BACKUP_DIR = "backups_tmp/"

def do_import(comment='', commit=None):

  if commit:
    repo = Repository()
    repo.git_revert(commit)
  
  ise = NetworkPolicies()
  ise.export_policy('taking backup for Import task')

  ise.create_policy_set(all_policy_sets=True, endingTag='_tmp')

  bck_policy_sets = ise.read_backup_tmp_policy_set()
  policies = bck_policy_sets['response']

  #delete old policy sets
  for data in policies:
    if data['name'] != 'Default':
      print("\n## Deleting policy_name: {}".format(data['name']))
      ise.del_policy_set(data['id'])
      print("## policy_name {} deleted".format(data['name']))

  #change policy sets name
  policies_result = ise.get_all_policy_set()
  policies = policies_result['response']

  for data in policies:
    if data['name'] != 'Default':
      add.update_policy_set(data)

def do_export(comment):

  ise = NetworkPolicies()
  ise.export_policy(comment)

  repo = Repository()
  repo.save_to_repo(comment)


def main():

    parser = argparse.ArgumentParser()

    # Adding optional argument
    parser.add_argument("-e", "--export", action="store_true")
    parser.add_argument("-i", "--import", action="store_true")
    parser.add_argument("--comment", help = "Include comments about changes", default=None)
    parser.add_argument("--rollback", help = "Include previos comit_id to rollback", default=None)
    parser.add_argument("--target", help = "Include target device", default=None)
    
    # Read arguments from command line and convert to a python dict
    args = vars(parser.parse_args())

    if args['export']:
      if not args['comment']:
        message = "Include comments about changes\n"
        message += 'usage: python ise_policy_mgr.py --export --comment "Comments about changes"\n'
      
        print(parser.exit(1, message=message))

      else:
        print("performing export policy sets")
        #usage: python ise_policy_mgr.py --export --comment "some comments"
        start = datetime.now()
        do_export(args['comment'])
        finish = datetime.now()
        duration = finish - start
        print('\n\n### Total Duration Task: {} sec.\n'.format(duration.seconds))

    elif args['import']:

      if args['rollback']:
        #usage: python ise_policy_mgr.py --import --rollback <commit_id>
        print("performing import with rollback")
        #print(args['rollback'])

        start = datetime.now()
        do_import(commit=args['rollback'])
        finish = datetime.now()
        duration = finish - start
        print('\n\n### Total Duration Task: {} sec.\n'.format(duration.seconds))

      else:
        print("performing import from previous version")
        #usage: python ise_policy_mgr.py --import

        start = datetime.now()
        do_import()
        finish = datetime.now()
        duration = finish - start
        print('\n\n### Total Duration Task: {} sec.\n'.format(duration.seconds))


    else:
      message = 'usage: python ise_policy_mgr.py [--export] [--import] [--comment "Comments about changes"] [--rollback "commit_id"]\n'
      print(parser.exit(1, message=message))


    

if __name__ == "__main__":
  main()
