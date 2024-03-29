import os, json, requests
import git
import shutil
from ciscoisesdk import IdentityServicesEngineAPI
from ciscoisesdk.exceptions import ApiError
from logger import Logger
from decouple import config


logger = Logger().logger

BACKUP_TMP = "../backups_tmp/"
BACKUP_DIR = "../repository/ise-policy-repository-https/policy_sets/"

ISE_REPOSITORY = config('ISE_REPOSITORY')
GIT_TOKEN = config('GIT_TOKEN')

class Repository(object):

    def __init__(self):
        if not os.path.exists(BACKUP_DIR):
            self.clone_repo()
        
        self.repo = git.Repo('../repository/ise-policy-repository-https')

        if not os.path.exists(BACKUP_DIR):
            os.mkdir(BACKUP_DIR)

    def clone_repo(self):
        # Check out via HTTPS
        logger.info("Cloning repository")
        cwd = os.getcwd()
        #print(cwd)
        os.chdir('../repository')    

        repo_replace = ISE_REPOSITORY.replace("https://www.github.com/", "")
        git_repo = 'https://{}@github.com/{}'.format(GIT_TOKEN, repo_replace)
        git.Repo.clone_from(git_repo, 'ise-policy-repository-https')
        logger.info("Cloning repository, Done!!")

 
    def add_repo(self, target='policy_sets'):

        logger.info("adding files to stagging area")
        # Provide a list of the files to stage
        self.repo.index.add(['policy_sets/'+target+'.yml'])
        logger.info("files added!")


    def commit_repo(self, comment):
        logger.info("Commit changes")
        self.repo.index.commit(comment)
        logger.info("commit done!")

    
    def push_repo(self):

        #push changes
        logger.info("Pushing changes")
        self.repo.remotes.origin.push()
        logger.info("Push Done!")


    def copy_from_tmp(self, target='policy_sets'):

        shutil.copy(BACKUP_TMP+target+'_tmp.yml', BACKUP_DIR+target+'.yml')


    def save_to_repo(self, comment, target=None):

        self.copy_from_tmp(target)
        self.add_repo(target)
        self.commit_repo(comment)
        self.push_repo()


    def git_revert(self, commit, comment='', target='policy_sets'):

        self.repo.git.checkout(commit)
        shutil.copy(BACKUP_DIR+target+'.yml', BACKUP_TMP+target+'_revert.yml')
        self.repo.git.checkout('main')
        shutil.copy(BACKUP_TMP+target+'_revert.yml', BACKUP_DIR+target+'.yml')
        self.add_repo(target)
        self.commit_repo(comment)
        self.push_repo()
