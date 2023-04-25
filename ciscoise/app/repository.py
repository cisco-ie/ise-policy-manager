import os, json, requests
import git
import shutil
from ciscoisesdk import IdentityServicesEngineAPI
from ciscoisesdk.exceptions import ApiError
from backupNetworkPolicies import BackupNetworkPolicies

BACKUP_TMP = "backups_tmp/"
BACKUP_DIR = "repository/ise-policy-repository-https/policy_sets/"

class Repository(object):

    def __init__(self):
        if not os.path.exists(BACKUP_DIR):
            self.clone_repo()
        
        self.repo = git.Repo('repository/ise-policy-repository-https')


    def clone_repo(self):
        # Check out via HTTPS
        print("Cloning repository")
        cwd = os.getcwd()
        #print(cwd)
        os.chdir(cwd+'/repository')    

        git.Repo.clone_from('https://wwwin-github.cisco.com/spa-ie/ise-policy-repository.git', 'ise-policy-repository-https')

 
    def add_repo(self, filename='policy_sets.yml'):

        print("adding files to stagging area")
        # Provide a list of the files to stage
        self.repo.index.add(['policy_sets/'+filename])
        print("files added!")


    def commit_repo(self, comment):

        print("Commit changes")
        self.repo.index.commit(comment)
        print("commit done!")

    
    def push_repo(self):

        #push changes
        print("Pushing changes")
        self.repo.remotes.origin.push()
        print("Push Done!")


    def copy_from_tmp(self):

        shutil.copy(BACKUP_TMP+'policy_sets_tmp.yml', BACKUP_DIR+'policy_sets.yml')


    def save_to_repo(self, comment):

        self.copy_from_tmp()
        self.add_repo()
        self.commit_repo(comment)
        self.push_repo()


    def git_revert(self, commit, comment=''):

        self.repo.git.checkout(commit)
        shutil.copy(BACKUP_DIR+'policy_sets.yml', BACKUP_TMP+'policy_sets_revert.yml')
        self.repo.git.checkout('main')
        shutil.copy(BACKUP_TMP+'policy_sets_revert.yml', BACKUP_DIR+'policy_sets.yml')
        self.add_repo()
        self.commit_repo(comment)
        self.push_repo()
