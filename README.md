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

Clone the repository. When cloning a repository the `.git` can be left off the end.

```bash
$ git clone https://www-github.cisco.com/spa-ie/ise-policy-manager.git
```

```bash
$ cd {git clone path}/ciscoise
$ docker-compose up -d
```

## Usage

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

## Support Information


### Support Contacts

* [Innovation Edge Dev Team](mailto:cisco-ie-dev@cisco.com)


## Authors / Contributors

* [Pablo Lencinas](mailto:plencina@cisco.com)
* [Jason Shoemaker](mailto:jashoema@cisco.com)


## License

This project is covered under the terms described in [LICENSE](./LICENSE)
