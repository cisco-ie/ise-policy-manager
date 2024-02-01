# ISE Policy Manager
ISE Policy Manager is a Python script Demo for Cisco ISE.

- Export Policy Sets from Cisco ISE (new configuration is saved to git repo). 
- Show customer how the configuration has been saved and versioned.
- Import Policy Sets to a previous configuration


## Getting Started

These instructions will get you a copy of the project up and running on your local machine. See the deployment section below for notes on how to deploy the project on a live system.

### Prerequisites

Appropriate access privileges to install Python packages and associated dependencies.

### Installing

#### Create a github repository to store policy sets
First, you need to create a github repository using your account to store all policy sets for export condition.
[Creating new repository]((https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-new-repository))
Choose a Repository name and check init README file.
You will use this repository link for env variables in the next section (ISE_REPOSITORY).
In order to upload (push) information to this repository, you have to create a personal access token
[Creating a personal access token](https://docs.github.com/en/enterprise-server@3.9/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)


#### Clone cisco ise repository
When cloning a repository the `.git` can be left off the end.

```bash
$ git clone https://github.com/cisco-ie/ise-policy-manager.git
```

```bash
$ cd {git clone path}/ciscoise
$ docker-compose up -d
```

Create a new .env file
```bash
$ cd {git clone path}/ciscoise/app
$ touch .env
```
and include this variables

```bash
ISE_USERNAME="username"
ISE_PASSWORD="password"
ISE_BASE_URL="https://CISCO_ISE_IP_ADDRESS"
ISE_VERSION="3.1_Patch_1"
ISE_REPOSITORY="https://www.github.com/plencina/ise_repo_test.git"
GIT_USERNAME="git_username"
GIT_TOKEN="git_token"
```

or you can create local environment variables in your system.
Use the export command to create the variables (only for linux or mac)
```bash
export ISE_USERNAME="username"
export ISE_PASSWORD="password"
export ISE_BASE_URL="https://CISCO_ISE_IP_ADDRESS"
export ISE_VERSION="3.1_Patch_1"
export ISE_REPOSITORY="https://www.github.com/pslencinas/test.git"
export GIT_USERNAME="git_username"
export GIT_TOKEN="git_token"
```

## Usage

### Precheck validation
```bash
# python ise-policy-mgr.py --precheck --target <hostnmae/IP>"
```
### Save to git repo
```bash
# python ise-policy-mgr.py --export --target <hostnmae/IP> --comment "Comments about changes"
```
### Deploy latest from git repo
```bash
# python ise-policy-mgr.py --import --target <hostnmae/IP>
```
### Deploy rollback to previous version of configuration
```bash
# python ise-policy-mgr.py --import --target <hostnmae/IP> --rollback <commit_id>
```

### Using local repository. You can use this args to work locally and not using a remote repository
```bash
# python ise-policy-mgr.py --export --target <hostnmae/IP> --localRepo
```
### Perform audit check with standard jinja template
```bash
# python ise-policy-mgr.py --audit --target <hostnmae/IP>
```
### Perform audit check with custom jinja template and audit file
```bash
# python ise-policy-mgr.py --audit --audit_file <policy sets to check> --template_name <jinja template to use>
```
## Support Information


## Authors / Contributors

* [Pablo Lencinas](mailto:plencina@cisco.com)
* [Jason Shoemaker](mailto:jashoema@cisco.com)


## License

This project is covered under the terms described in [LICENSE](./LICENSE)
