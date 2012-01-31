#!/usr/bin/env python

import argparse
import getpass
import logging
import os
import re
import subprocess
import socket
import sys


def list(username, hostname, reporoot, regexFilter=None):
    command = ['ssh', '%s@%s' % (username, hostname), 'find', reporoot, '-name', '*.git']

    stdout = subprocess.check_output(command)
    repos = stdout.strip().split("\n")
    
    regex = re.compile(regexFilter) if regexFilter else None
    
    selected_repos = []
    for repo in repos:
        if regex is None or regex.search(repo):
            selected_repos.append(repo)
    
    return selected_repos


def clone(username, hostname, repo, destination):
    command = ['git', 'clone', '%s@%s:%s' % (username, hostname, repo), destination]
    subprocess.call(command) 



#Command Handlers
def listCommandHandler(args):
    """
    """
    log = logging.getLogger("listCommandHandler")

    repos = list(args.username, args.hostname, args.reporoot, args.filter) 
    if repos:
        log.info("\n".join(repos))

listCommandHandler.examples = """
"""


def cloneCommandHandler(args):
    """
    """
    log = logging.getLogger("cloneCommandHandler")

    selected_repos = list(args.username, args.hostname, args.reporoot, args.filter)

    repoDest = {}
    for repo in selected_repos:
        if args.no_mirror:
            destination = os.path.join(args.output_directory, repo.split("/")[-1])
        else:
            destination = os.path.join(args.output_directory, repo.replace(args.reporoot,"").replace(".git", ""))
        
        if os.path.exists(destination):
            log.info("Skipping repo: %s - %s already exists." % (repo, destination))
        else:
            repoDest[repo] = destination
   

    if repoDest:
        log.info("\nContinuing will clone repos as follows:\n")
        for repo, dest in repoDest.items():
            log.info("   %s:%s => %s" % (args.hostname, repo, dest))
        
        confirmation = raw_input("Clone repos [y/n]:")
        if confirmation.strip().lower() == 'y':
            for repo, dest in repoDest.items():
                clone(args.username, args.hostname, repo, dest)
    else:
        log.info("No repos need cloning.")


cloneCommandHandler.examples = """Examples:
    repoutil.py clone             #Clone all repos not yet cloned
    repoutil.py -u jmullins clone #Clone all repos not yet cloned (username jmullins)
    repoutil.py clone -f 'tech.*' #Clone all repos matching regex
    repoutil.py clone -o dev      #Clone all repos to directory 'dev'
    repoutil.py clone -o dev -M   #Clone all repos to directory dev without mirroring remote directory structure
"""


def main(argv):

    def parse_arguments():
        parser = argparse.ArgumentParser(description="repotutil.py is a helper for working with 30and30 git repositories.")
        parser.add_argument("-u", "--username", default=getpass.getuser())
        parser.add_argument("-H", "--hostname", default="dev.30and30.com")
        parser.add_argument("-r", "--reporoot", default="/30and30/repos/")

        commandParsers = parser.add_subparsers()

        #list parser
        listCommandParser = commandParsers.add_parser(
                "list",
                help="list available git repos",
                description=listCommandHandler.__doc__,
                epilog=listCommandHandler.examples,
                formatter_class=argparse.RawDescriptionHelpFormatter
                )
        listCommandParser.set_defaults(command="list", commandHandler=listCommandHandler)
        listCommandParser.add_argument("-f", "--filter", help="regular expression filter")

        #clone parser
        cloneCommandParser = commandParsers.add_parser(
                "clone",
                help="clone selected git repos",
                description=cloneCommandHandler.__doc__,
                epilog=cloneCommandHandler.examples,
                formatter_class=argparse.RawDescriptionHelpFormatter
                )
        cloneCommandParser.set_defaults(command="clone", commandHandler=cloneCommandHandler)
        cloneCommandParser.add_argument("-f", "--filter", help="regular expression filter")
        cloneCommandParser.add_argument("-o", "--output-directory", default=".")
        cloneCommandParser.add_argument("-M", "--no-mirror", action="store_true", help="Do not mirror repo directory structure.")

        return parser.parse_args(argv[1:])


    #configure logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setLevel(logging.INFO)
    logger.addHandler(consoleHandler)
    
    log = logging.getLogger("main")

    args = parse_arguments()

    try:
        socket.setdefaulttimeout(10)

        #Invoke command handler
        args.commandHandler(args)

        return 0
    
    except KeyboardInterrupt:
        return 1
    
    except Exception as error:
        log.error("Unhandled exception: %s" % str(error))
        return 2

if __name__ == '__main__':
    sys.exit(main(sys.argv))
    
