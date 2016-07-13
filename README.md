## The BigFix Integration GIT Repo

### Subprojects
#### Fletch

The fulfillment of use cases #1 and #2 as part of the phase II integration. This project, designed to be used in Pycharm IDE, listens to output from a cb-event-forwarder, and processes the output. It has been built to do a few tasks:

1. Look for vulnerable apps executing
2. Attribute detection events to vulnerable apps
3. Look for banned flies attempting to execute

For all of these tasks, we send the information over to BigFix in some form for them to display to a user.

#### Punisher

This sub-project is for the small python-based service that gets deployed to Cb Protection servers which, on some time interval, polls the Cb Protection server for all banned files across the enterprise, and informs BigFix of their presence (through the creation of fixlets).

There are two parts to this:

1. The python code capable of doing all the functionality
2. A small visual studio installer project that builds the MSI able to install the python code after it has been wrapped up in a self-contained EXE through the use of pyinstaller.
