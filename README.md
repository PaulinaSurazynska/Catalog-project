# About catalog-project
This applications consists of a list of countries and cities with third party user registration (in order to log to application you need to have google or facebook account) and authentication system.
Logged users have ablity to create/edit/delete countries or/and cities they created.

# Project files:
* catalog.dg - it's a database file containing some example of countries and cities to get started.
* catalog.opy - file contains the whole server side programming logic of the application.
* fb_client_secret.json and google_client_secrtets.json - authorization information for Facebook and Google+ authentication. 
* templates folder - contains all the template files used in the application
* static - folder contains bootstrap styling

# Run application
In order to start the application you need to :
* Download and install [Vagrant](https://www.vagrantup.com/downloads.html)
* Download and install [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
* Clone the [fullstack-nanodegree-vm repository](https://github.com/udacity/fullstack-nanodegree-vm)
* Open directory and navigate to `vagrant/` sub-directory
* Download or clone this repo and navigate to it.
* Open the terminal and run virtualMachine ( `vagrant up` and `vagrant ssh`)
* To access shared  files type `cd /vagrant` ( to check what folders it consist you can run `ls` command)
* Navigate to catalog-folder (by running `cd catalog/catalog-folder`)
* Start local server by typig `python catalog.py`
* Open browser at `localhost://5000/`
* Explore the application!:D
